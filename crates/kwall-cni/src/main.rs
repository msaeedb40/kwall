use std::env;
use std::io::Read;
use anyhow::Result;
use kwall_cni::{create_netkit_pair, notify_agent_register, notify_agent_unregister};

#[tokio::main]
async fn main() -> Result<()> {
    let command = env::var("CNI_COMMAND").unwrap_or_else(|_| "ADD".into());
    let container_id = env::var("CNI_CONTAINERID").unwrap_or_else(|_| "test-container".into());
    let ifname = env::var("CNI_IFNAME").unwrap_or_else(|_| "eth0".into());

    let mut stdin_buf = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut stdin_buf);

    match command.as_str() {
        "ADD" => {
            let pair = create_netkit_pair(&container_id, &ifname)?;
            // Notify local agent
            let _ = notify_agent_register(0x0A000002, 1001, 1, 0, 10).await;

            // Output minimal CNI SUCCESS JSON result
            println!(
                r#"{{
  "cniVersion": "1.0.0",
  "interfaces": [
    {{"name": "{}"}},
    {{"name": "{}"}}
  ],
  "ips": [
    {{
      "version": "4",
      "address": "10.0.0.2/24",
      "interface": 1
    }}
  ]
}}"#,
                pair.host_ifname, pair.container_ifname
            );
        }
        "DEL" => {
            let _ = notify_agent_unregister(0x0A000002).await;
        }
        "CHECK" => {}
        _ => {}
    }

    Ok(())
}
