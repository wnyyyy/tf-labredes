use tf::network::config::INTERFACE_NAME;
use tf::network::dhcp_server;
use tf::network::fake_gateway::start_gateway_simulation;

fn main() {
    std::thread::spawn(|| {
        start_gateway_simulation(INTERFACE_NAME);
    });
    
    dhcp_server::run();
}