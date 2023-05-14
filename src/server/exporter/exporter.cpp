#include "exporter.hpp"

extern int port;

auto registry = std::make_shared<prometheus::Registry>();

void run_exporter() {
    std::ostringstream oss;

    oss << "127.0.0.1:" << port;

    // create an http server running on port 8080
    prometheus::Exposer exposer{ oss.str() };

    // ask the exposer to scrape the registry on incoming HTTP requests
    exposer.RegisterCollectable(registry);

    std::cout << "Server is running at " << BLUE("http://" + oss.str() + "/metrics\n");
}