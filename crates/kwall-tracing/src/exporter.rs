//! OpenTelemetry (OTel) OTLP and Jaeger standard trace format serializers.
//!
//! Formats distributed kernel spans into standard OTLP JSON (v1/traces) and Jaeger JSON batches
//! for ingestion by OpenTelemetry Collectors, Jaeger, Grafana Tempo, and Zipkin.

use serde::{Deserialize, Serialize};

use crate::kernel_trace::DistributedSpan;

/// OpenTelemetry OTLP JSON Schema structures per OpenTelemetry Trace Data Model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtlpKeyValue {
    pub key: String,
    pub value: OtlpAnyValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtlpAnyValue {
    #[serde(rename = "stringValue", skip_serializing_if = "Option::is_none")]
    pub string_value: Option<String>,
    #[serde(rename = "intValue", skip_serializing_if = "Option::is_none")]
    pub int_value: Option<i64>,
    #[serde(rename = "boolValue", skip_serializing_if = "Option::is_none")]
    pub bool_value: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtlpSpanStatus {
    pub code: u32, // 0 = Unset, 1 = Ok, 2 = Error
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtlpSpan {
    #[serde(rename = "traceId")]
    pub trace_id: String,
    #[serde(rename = "spanId")]
    pub span_id: String,
    #[serde(rename = "parentSpanId", skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,
    pub name: String,
    pub kind: u32, // 1 = Internal, 2 = Server, 3 = Client
    #[serde(rename = "startTimeUnixNano")]
    pub start_time_unix_nano: String,
    #[serde(rename = "endTimeUnixNano")]
    pub end_time_unix_nano: String,
    pub attributes: Vec<OtlpKeyValue>,
    pub status: OtlpSpanStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtlpScopeSpans {
    pub scope: OtlpScope,
    pub spans: Vec<OtlpSpan>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtlpScope {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtlpResource {
    pub attributes: Vec<OtlpKeyValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtlpResourceSpans {
    pub resource: OtlpResource,
    #[serde(rename = "scopeSpans")]
    pub scope_spans: Vec<OtlpScopeSpans>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtlpExportTraceServiceRequest {
    #[serde(rename = "resourceSpans")]
    pub resource_spans: Vec<OtlpResourceSpans>,
}

/// Serializer for OpenTelemetry and Jaeger trace data formats.
pub struct TraceExporter;

impl TraceExporter {
    /// Serializes distributed spans into standard OpenTelemetry OTLP JSON (v1/traces).
    #[must_use]
    pub fn to_otlp_json(service_name: &str, spans: &[DistributedSpan]) -> String {
        let mut otlp_spans = Vec::with_capacity(spans.len());

        for span in spans {
            let mut attrs = Vec::new();
            for (k, v) in &span.attributes {
                attrs.push(OtlpKeyValue {
                    key: k.clone(),
                    value: OtlpAnyValue {
                        string_value: Some(v.clone()),
                        int_value: None,
                        bool_value: None,
                    },
                });
            }

            let status_code = if span.error { 2 } else { 1 };
            let status_msg = if span.error {
                Some(format!("HTTP Error {}", span.status_code))
            } else {
                None
            };

            otlp_spans.push(OtlpSpan {
                trace_id: span.trace_id.clone(),
                span_id: span.span_id.clone(),
                parent_span_id: span.parent_span_id.clone(),
                name: span.operation_name.clone(),
                kind: 2, // Server
                start_time_unix_nano: span.start_time_ns.to_string(),
                end_time_unix_nano: span.end_time_ns.to_string(),
                attributes: attrs,
                status: OtlpSpanStatus {
                    code: status_code,
                    message: status_msg,
                },
            });
        }

        let resource_attrs = vec![
            OtlpKeyValue {
                key: "service.name".to_string(),
                value: OtlpAnyValue {
                    string_value: Some(service_name.to_string()),
                    int_value: None,
                    bool_value: None,
                },
            },
            OtlpKeyValue {
                key: "telemetry.sdk.name".to_string(),
                value: OtlpAnyValue {
                    string_value: Some("kwall-ebpf".to_string()),
                    int_value: None,
                    bool_value: None,
                },
            },
        ];

        let req = OtlpExportTraceServiceRequest {
            resource_spans: vec![OtlpResourceSpans {
                resource: OtlpResource {
                    attributes: resource_attrs,
                },
                scope_spans: vec![OtlpScopeSpans {
                    scope: OtlpScope {
                        name: "kwall-tracing".to_string(),
                        version: "0.1.0".to_string(),
                    },
                    spans: otlp_spans,
                }],
            }],
        };

        serde_json::to_string_pretty(&req).unwrap_or_else(|_| "{}".to_string())
    }

    /// Serializes distributed spans into Jaeger Batch JSON format.
    #[must_use]
    pub fn to_jaeger_json(service_name: &str, spans: &[DistributedSpan]) -> String {
        let jaeger_batch = serde_json::json!({
            "process": {
                "serviceName": service_name,
                "tags": [
                    { "key": "kwall.tracer", "type": "string", "value": "ebpf" }
                ]
            },
            "spans": spans.iter().map(|s| {
                serde_json::json!({
                    "traceID": s.trace_id,
                    "spanID": s.span_id,
                    "operationName": s.operation_name,
                    "startTime": s.start_time_ns / 1000, // microseconds
                    "duration": s.duration_ns / 1000,
                    "tags": s.attributes.iter().map(|(k, v)| {
                        serde_json::json!({ "key": k, "type": "string", "value": v })
                    }).collect::<Vec<_>>()
                })
            }).collect::<Vec<_>>()
        });

        serde_json::to_string_pretty(&jaeger_batch).unwrap_or_else(|_| "{}".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_otlp_json_export() {
        let mut attrs = HashMap::new();
        attrs.insert("http.status_code".to_string(), "200".to_string());

        let span = DistributedSpan {
            trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
            span_id: "00f067aa0ba902b7".to_string(),
            parent_span_id: None,
            service_name: "checkout".to_string(),
            operation_name: "POST /checkout".to_string(),
            start_time_ns: 1_000_000_000,
            end_time_ns: 1_010_000_000,
            duration_ns: 10_000_000,
            status_code: 200,
            error: false,
            attributes: attrs,
            events: Vec::new(),
        };

        let otlp_json = TraceExporter::to_otlp_json("checkout-svc", &[span]);
        assert!(otlp_json.contains("resourceSpans"));
        assert!(otlp_json.contains("4bf92f3577b34da6a3ce929d0e0e4736"));
        assert!(otlp_json.contains("checkout-svc"));
    }

    #[test]
    fn test_jaeger_json_export() {
        let span = DistributedSpan {
            trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
            span_id: "00f067aa0ba902b7".to_string(),
            parent_span_id: None,
            service_name: "billing".to_string(),
            operation_name: "GET /invoice".to_string(),
            start_time_ns: 1_000_000_000,
            end_time_ns: 1_005_000_000,
            duration_ns: 5_000_000,
            status_code: 200,
            error: false,
            attributes: HashMap::new(),
            events: Vec::new(),
        };

        let jaeger_json = TraceExporter::to_jaeger_json("billing-svc", &[span]);
        assert!(jaeger_json.contains("billing-svc"));
        assert!(jaeger_json.contains("traceID"));
    }
}
