extern crate pnet;

use tf::network;

fn main() {
    network::dhcp_server::run();
}
