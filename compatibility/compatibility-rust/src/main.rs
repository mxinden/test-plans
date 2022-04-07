use env_logger::Env;
use libp2p::futures::StreamExt;
use libp2p::swarm::{Swarm, SwarmEvent};
use libp2p::{identity, multiaddr::Protocol, ping, Multiaddr, PeerId};

const LISTENING_PORT: u16 = 1234;

#[async_std::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();

    let (client, run_params) = testground::client::Client::new().await?;

    client.wait_network_initialized().await?;

    let seq = client
        .signal_and_wait("ip-allocation", run_params.test_instance_count)
        .await?;

    println!("Seq is: {:?}", seq);

    let ip_addr = match run_params.test_subnet {
        ipnetwork::IpNetwork::V4(network) => {
            let mut octets = network.ip().octets();
            octets[2] = ((seq >> 8) + 1) as u8;
            octets[3] = seq as u8;
            octets.into()
        }
        _ => unimplemented!(),
    };

    client
        .configure_network(testground::network_conf::NetworkConfiguration {
            network: "default".to_string(),
            ipv4: Some(ipnetwork::Ipv4Network::new(ip_addr, 32).unwrap()),
            ipv6: None,
            enable: true,
            default: testground::network_conf::LinkShape {
                latency: 10000000,
                jitter: 0,
                bandwidth: 1048576,
                filter: testground::network_conf::FilterAction::Accept,
                loss: 0.0,
                corrupt: 0.0,
                corrupt_corr: 0.0,
                reorder: 0.0,
                reorder_corr: 0.0,
                duplicate: 0.0,
                duplicate_corr: 0.0,
            },
            rules: None,
            callback_state: "network-configured".to_string(),
            callback_target: None,
            routing_policy: testground::network_conf::RoutingPolicyType::AllowAll,
        })
        .await?;

    let mut swarm = {
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());
        println!("Local peer id: {:?}", local_peer_id);

        Swarm::new(
            libp2p::development_transport(local_key).await?,
            ping::Behaviour::new(ping::Config::new().with_keep_alive(true)),
            local_peer_id,
        )
    };

    let addr: Multiaddr = {
        Multiaddr::empty()
            .with(Protocol::Ip4({
                let mut octets = ip_addr.octets();
                octets[3] = 1;
                octets.into()
            }))
            .with(Protocol::Tcp(LISTENING_PORT))
    };

    match seq {
        1 => {
            println!("Test instance, listening for incoming connections.");
            swarm.listen_on(addr)?;
            // TODO: Should we wait for the listen events?
            client.signal("listening".to_string()).await?;
        }
        _ => {
            println!("Test instance, connecting to listening instance.");
            client.barrier("listening".to_string(), 1).await?;
            swarm.dial(addr)?;
        }
    }

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => println!("Listening on {:?}", address),
            SwarmEvent::Behaviour(event) => {
                println!("Ping event: {:?}", event);
                break;
            }
            _ => {}
        }
    }

    client.record_success().await?;

    Ok(())
}
