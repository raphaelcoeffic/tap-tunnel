use std::io;
use std::net::IpAddr;

use futures::TryStreamExt;
use rtnetlink::{Handle, RouteMessageBuilder};

/// Look up a network interface index by name.
async fn get_link_index(handle: &Handle, iface_name: &str) -> io::Result<u32> {
    let mut links = handle
        .link()
        .get()
        .match_name(iface_name.to_string())
        .execute();

    let link = links
        .try_next()
        .await
        .map_err(|e| io::Error::other(format!("failed to query link {}: {}", iface_name, e)))?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("interface {} not found", iface_name),
            )
        })?;

    Ok(link.header.index)
}

/// Add a device route for the given destination via the named interface.
///
/// Equivalent to: `ip route add <dest>/<prefix_len> dev <iface_name>`
pub async fn add_route(
    handle: &Handle,
    iface_name: &str,
    dest: IpAddr,
    prefix_len: u8,
) -> io::Result<()> {
    let index = get_link_index(handle, iface_name).await?;

    let route_msg = match dest {
        IpAddr::V4(v4) => RouteMessageBuilder::<std::net::Ipv4Addr>::new()
            .destination_prefix(v4, prefix_len)
            .output_interface(index)
            .build(),
        IpAddr::V6(v6) => RouteMessageBuilder::<std::net::Ipv6Addr>::new()
            .destination_prefix(v6, prefix_len)
            .output_interface(index)
            .build(),
    };

    handle
        .route()
        .add(route_msg)
        .execute()
        .await
        .map_err(|e| io::Error::other(format!("failed to add route: {}", e)))
}

/// Remove a device route for the given destination via the named interface.
///
/// Equivalent to: `ip route del <dest>/<prefix_len> dev <iface_name>`
pub async fn remove_route(
    handle: &Handle,
    iface_name: &str,
    dest: IpAddr,
    prefix_len: u8,
) -> io::Result<()> {
    let index = get_link_index(handle, iface_name).await?;

    // Build a RouteMessage that matches what we want to delete.
    // For deletion, we construct the same route message as we would for add.
    let route_msg = match dest {
        IpAddr::V4(v4) => RouteMessageBuilder::<std::net::Ipv4Addr>::new()
            .destination_prefix(v4, prefix_len)
            .output_interface(index)
            .build(),
        IpAddr::V6(v6) => RouteMessageBuilder::<std::net::Ipv6Addr>::new()
            .destination_prefix(v6, prefix_len)
            .output_interface(index)
            .build(),
    };

    handle
        .route()
        .del(route_msg)
        .execute()
        .await
        .map_err(|e| io::Error::other(format!("failed to delete route: {}", e)))
}
