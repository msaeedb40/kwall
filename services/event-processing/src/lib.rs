//! # kwall-event-processing: Distributed Event Streaming Bus
//!
//! High-throughput event streaming integration supporting NATS JetStream and Apache Kafka.
//! Provides partitioned event delivery, adaptive backpressure, and zero-copy binary
//! serialisation for all KWALL security telemetry.
//!
//! ## Modules
//!
//! - **`stream`**: `StreamBus` with NATS JetStream, Kafka, and in-process backends.

pub mod stream;

pub use stream::{
    KafkaConfig, NatsConfig, StreamBackend, StreamBus, StreamBusStats, StreamError, StreamEvent,
};
