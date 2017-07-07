#[macro_use]
extern crate clap;
extern crate colored;

use colored::*;
use clap::{App, Arg, ArgMatches};
use std::net::Ipv4Addr;

fn to_int(addr: Ipv4Addr) -> u32 {
    let ip = addr.octets();
    ((ip[0] as u32) << 24) + ((ip[1] as u32) << 16) + ((ip[2] as u32) << 8) + (ip[3] as u32)
}

fn to_ip(addr: u32) -> Ipv4Addr {
    Ipv4Addr::from(addr)
}

fn network_address(address: Ipv4Addr, netmask: Ipv4Addr) -> Ipv4Addr {
    to_ip(to_int(address) & to_int(netmask))
}

fn broadcast_address(network_address: Ipv4Addr, netmask: Ipv4Addr) -> Ipv4Addr {
    let inverted = invert(netmask);
    to_ip(to_int(network_address) | to_int(inverted))
}

fn invert(ip: Ipv4Addr) -> Ipv4Addr {
    let octets = ip.octets();
    Ipv4Addr::new(!octets[0], !octets[1], !octets[2], !octets[3])
}

fn cidr(ip: Ipv4Addr) -> usize {
    let binary = format!("{:b}", to_int(ip)).to_string();
    binary.matches("1").count()
}

fn print_output(address: Ipv4Addr, netmask: Ipv4Addr) {
    let network = network_address(address, netmask);
    let broadcast = broadcast_address(network, netmask);
    let cidr = cidr(netmask);
    let host_min = to_ip(to_int(network) + 1);
    let host_max = to_ip(to_int(broadcast) - 1);

    println!("Address:   {ip}", ip = address.to_string().blue());
    println!("Netmask:   {ip} = {cidr}", ip = netmask.to_string().blue(), cidr = cidr.to_string().blue());
    println!("Wildcard:  {ip}", ip = invert(netmask).to_string().blue());
    println!("Network:   {ip}", ip = network.to_string().blue());

    println!("HostMin:   {ip}", ip = host_min.to_string().blue());

    println!("HostMax:   {ip}", ip = host_max.to_string().blue());
    println!("Broadcast: {ip}", ip = broadcast.to_string().blue());
    println!("Hosts:     {}", format!("{}", (to_int(broadcast) - to_int(host_min))).blue());
}

fn parse_args() -> ArgMatches<'static> {
    App::new("yes")
        .version(crate_version!())
        .author(crate_authors!())
        .arg(Arg::with_name("ADDRESS")
            .index(1))
        .arg(Arg::with_name("NETMASK")
            .index(2))
        .get_matches()
}

fn main() {
    let args = parse_args();

    let address: Ipv4Addr = match args.value_of("ADDRESS").unwrap_or("192.168.1.0").parse() {
        Ok(ip) => ip,
        Err(_) => {
            println!("{}", "Invalid IP address".red());
            Ipv4Addr::new(192, 168, 0, 1)
        }
    };

    let netmask: Ipv4Addr = match args.value_of("NETMASK").unwrap_or("255.255.255.0").parse() {
        Ok(ip) => ip,
        Err(_) => {
            println!("{}", "Invalid netmask address".red());
            Ipv4Addr::new(255, 255, 255, 0)
        }
    };

    print_output(address, netmask);
}
