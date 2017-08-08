#[macro_use]
extern crate clap;
extern crate colored;
extern crate regex;

use std::cmp;
use colored::*;
use clap::{Arg, ArgMatches};
use std::net::Ipv4Addr;
use regex::Regex;
use std::process;

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

fn broadcast_address(host: Ipv4Addr, netmask: Ipv4Addr) -> Ipv4Addr {
    let inverted = invert(netmask);
    to_ip(to_int(host) | to_int(inverted))
}

fn invert(ip: Ipv4Addr) -> Ipv4Addr {
    let octets = ip.octets();
    Ipv4Addr::new(!octets[0], !octets[1], !octets[2], !octets[3])
}

fn cidr(ip: Ipv4Addr) -> usize {
    let binary = format!("{:b}", to_int(ip)).to_string();
    binary.matches('1').count()
}

fn netmask_from_cidr(cidr: &str) -> Ipv4Addr {
    let mut mask: [u8; 4] = [0, 0, 0, 0];
    let mut c = cidr.parse::<u32>().unwrap();

    for i in 0..4 {
        let n = cmp::min(c, 8);
        mask[i] = (256 - 2u32.pow(8 - n)) as u8;
        c -= n;
    }
    Ipv4Addr::new(mask[0], mask[1], mask[2], mask[3])
}

fn print_output(address: Ipv4Addr, netmask: Ipv4Addr) {
    let network = network_address(address, netmask);
    let broadcast = broadcast_address(address, netmask);
    let cidr = cidr(netmask);
    let host_min = to_ip(to_int(network) + 1);
    let host_max = to_ip(to_int(broadcast) - 1);

    println!("Address:   {ip}", ip = address.to_string().blue());
    println!(
        "Netmask:   {ip} = {cidr}",
        ip = netmask.to_string().blue(),
        cidr = cidr.to_string().blue()
    );
    println!("Wildcard:  {ip}", ip = invert(netmask).to_string().blue());
    println!("----");
    println!(
        "Network:   {ip}/{cidr}",
        ip = network.to_string().blue(),
        cidr = cidr.to_string().blue()
    );
    println!("Broadcast: {ip}", ip = broadcast.to_string().blue());

    println!("HostMin:   {ip}", ip = host_min.to_string().blue());

    println!("HostMax:   {ip}", ip = host_max.to_string().blue());

    if cidr < 32 {
        println!(
            "Hosts:     {}",
            format!("{}", (to_int(broadcast) - to_int(host_min))).blue()
        );
    }
}

fn parse_args() -> ArgMatches<'static> {
    app_from_crate!()
        .arg(Arg::with_name("ADDRESS").index(1))
        .arg(Arg::with_name("NETMASK").index(2))
        .get_matches()
}

fn display_error(msg: &str) {
    println!("{}", msg.red());
}

fn main() {
    let args = parse_args();

    let mut netmask_str = args.value_of("NETMASK").unwrap_or("255.255.255.0");
    let mut address_str = args.value_of("ADDRESS").unwrap_or("192.168.1.0");

    let address_alone = Regex::new(r"^\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}$").unwrap();
    let address_cidr = Regex::new(r"^\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}/\d{1,2}$").unwrap();

    if address_alone.is_match(address_str) {
        // Expected format
    } else if address_cidr.is_match(address_str) {
        let d: Vec<_> = address_str.split('/').collect();
        address_str = d[0];
        netmask_str = d[1];
    } else {
        display_error("Unable to determine address/netmask format from input");
        process::exit(1);
    }

    let address = address_str.parse::<Ipv4Addr>().unwrap_or({
        Ipv4Addr::new(192, 168, 0, 1)
    });

    let netmask = if netmask_str.len() <= 2 {
        netmask_from_cidr(netmask_str)
    } else {
        netmask_str.parse::<Ipv4Addr>().unwrap_or({
            Ipv4Addr::new(255, 255, 255, 0)
        })
    };

    print_output(address, netmask);
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn to_int_test() {
        let mut addr: Ipv4Addr = Ipv4Addr::from(0);
        assert_eq!(to_int(addr), 0);

        addr = Ipv4Addr::from([255, 255, 255, 255]);
        assert_eq!(to_int(addr), 4294967295);
    }

    #[test]
    fn to_ip_test() {
        let mut number = 0;
        assert_eq!(to_ip(number), Ipv4Addr::from([0, 0, 0, 0]));

        number = 4294967295;
        assert_eq!(to_ip(number), Ipv4Addr::from([255, 255, 255, 255]));
    }

    #[test]
    fn network_address_test() {
        let expected = Ipv4Addr::from([192, 168, 1, 0]);

        let address = Ipv4Addr::from([192, 168, 1, 100]);
        let netmask = Ipv4Addr::from([255, 255, 255, 0]);

        assert_eq!(expected, network_address(address, netmask));
    }

    #[test]
    fn broadcast_test() {
        let expected = Ipv4Addr::from([192, 168, 1, 255]);

        let address = Ipv4Addr::from([192, 168, 1, 100]);
        let netmask = Ipv4Addr::from([255, 255, 255, 0]);

        let broadcast = broadcast_address(address, netmask);

        assert_eq!(expected, broadcast);
    }

    #[test]
    fn cidr_test() {
        assert_eq!(32, cidr(Ipv4Addr::from([255, 255, 255, 255])));
        assert_eq!(31, cidr(Ipv4Addr::from([255, 255, 255, 254])));
        assert_eq!(30, cidr(Ipv4Addr::from([255, 255, 255, 252])));
        assert_eq!(29, cidr(Ipv4Addr::from([255, 255, 255, 248])));
        assert_eq!(0, cidr(Ipv4Addr::from([0, 0, 0, 0])));
    }

    #[test]
    fn netmask_from_cidr_test() {
        assert_eq!(
            Ipv4Addr::from([255, 255, 255, 255]),
            netmask_from_cidr(format!("{}", 32).as_ref())
        );
        assert_eq!(
            Ipv4Addr::from([255, 255, 255, 254]),
            netmask_from_cidr(format!("{}", 31).as_ref())
        );
        assert_eq!(
            Ipv4Addr::from([255, 255, 255, 252]),
            netmask_from_cidr(format!("{}", 30).as_ref())
        );
        assert_eq!(
            Ipv4Addr::from([0, 0, 0, 0]),
            netmask_from_cidr(format!("{}", 0).as_ref())
        );
    }
}
