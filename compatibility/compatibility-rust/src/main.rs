use std::collections::HashSet;
use std::str::FromStr;

use env_logger::Env;
use futures::FutureExt;
use libp2p::futures::StreamExt;
use libp2p::swarm::{Swarm, SwarmEvent};
use libp2p::{identity, multiaddr::Protocol, ping, Multiaddr, PeerId};

const LISTENING_PORT: u16 = 1234;

#[async_std::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();

    let (client, run_params) = testground::client::Client::new().await?;

    client
        .signal_and_wait("initialized_global", run_params.test_instance_count)
        .await?;

    client.wait_network_initialized().await?;

    // let ip_addr = match run_params.test_subnet {
    //     ipnetwork::IpNetwork::V4(network) => {
    //         let mut octets = network.ip().octets();
    //         octets[2] = ((seq >> 8) + 1) as u8;
    //         octets[3] = seq as u8;
    //         octets.into()
    //     }
    //     _ => unimplemented!(),
    // };

    // client
    //     .configure_network(testground::network_conf::NetworkConfiguration {
    //         network: "default".to_string(),
    //         ipv4: Some(ipnetwork::Ipv4Network::new(ip_addr, 32).unwrap()),
    //         ipv6: None,
    //         enable: true,
    //         default: testground::network_conf::LinkShape {
    //             latency: 10000000,
    //             jitter: 0,
    //             bandwidth: 1048576,
    //             filter: testground::network_conf::FilterAction::Accept,
    //             loss: 0.0,
    //             corrupt: 0.0,
    //             corrupt_corr: 0.0,
    //             reorder: 0.0,
    //             reorder_corr: 0.0,
    //             duplicate: 0.0,
    //             duplicate_corr: 0.0,
    //         },
    //         rules: None,
    //         callback_state: "network-configured".to_string(),
    //         callback_target: None,
    //         routing_policy: testground::network_conf::RoutingPolicyType::AllowAll,
    //     })
    //     .await?;

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

    let local_addr: Multiaddr = {
        let ip_addr = match if_addrs::get_if_addrs()
            .unwrap()
            .into_iter()
            .find(|iface| iface.name == "eth1")
            .unwrap()
            .addr
            .ip()
        {
            std::net::IpAddr::V4(addr) => addr,
            std::net::IpAddr::V6(_) => unimplemented!(),
        };

        Multiaddr::empty()
            .with(Protocol::Ip4(ip_addr))
            .with(Protocol::Tcp(LISTENING_PORT))
    };

    println!(
        "Test instance, listening for incoming connections on: {:?}.",
        local_addr
    );
    swarm.listen_on(local_addr.clone())?;

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                assert_eq!(address, local_addr);
                break;
            }
            _ => unreachable!(),
        }
    }

    let mut address_stream = client
        .subscribe("addresses")
        .await
        .take(run_params.test_instance_count as usize)
        .map(|a| Multiaddr::from_str(&a.unwrap()).unwrap())
        // Note: we sidestep simultaneous connect issues by ONLY connecting to peers
        // who published their addresses before us (this is enough to dedup and avoid
        // two peers dialling each other at the same time).
        //
        // We can do this because sync service pubsub is ordered.
        .take_while(|a| futures::future::ready(a != &local_addr));

    client.publish("addresses", local_addr.to_string()).await?;

    while let Some(addr) = address_stream.next().await {
        swarm.dial(addr).unwrap();
    }

    let mut connected = HashSet::new();
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                connected.insert(peer_id);
                if connected.len() == run_params.test_instance_count as usize - 1 {
                    break;
                }
            }
            e => {
                println!("Event: {:?}", e)
            }
        }
    }

    client
        .signal_and_wait("connected", run_params.test_instance_count)
        .await?;

    let mut pinged = HashSet::new();

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::Behaviour(ping::PingEvent {
                peer,
                result: Ok(ping::PingSuccess::Ping { .. }),
            }) => {
                pinged.insert(peer);
                if pinged.len() == run_params.test_instance_count as usize - 1 {
                    break;
                }
            }
            e => {
                println!("Event: {:?}", e)
            }
        }
    }

    {
        let all_instances_done = client
            .signal_and_wait("initial", run_params.test_instance_count)
            .boxed_local();
        let mut stream = swarm.take_until(all_instances_done);
        loop {
            match stream.next().await {
                Some(e) => {
                    println!("Event: {:?}", e)
                }
                None => break,
            }
        }
    }

    client.record_success().await?;

    Ok(())
}
