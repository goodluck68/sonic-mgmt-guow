# BGP Suppress FIB Pending
**Table of Contents**
- [BGP Suppress FIB Pending](#bgp-suppress-fib-pending)
- [1. Introduce Feature](#1-introduce-feature)
  - [1.1 Router receive a BGP route](#11-router-receive-a-bgp-route)
  - [1.2 Routing Information Base \& Forwarding Information Base](#12-routing-information-base--forwarding-information-base)
  - [1.3 Route Selection](#13-route-selection)
  - [1.4 Important BGP knowledge](#14-important-bgp-knowledge)
    - [1.4.1 Loop Prevention](#141-loop-prevention)
    - [1.4.2 Difference between `network`/`redistribute`/`aggregate`](#142-difference-between-networkredistributeaggregate)
    - [1.4.3 BGP route aggregation attributes](#143-bgp-route-aggregation-attributes)
  - [1.4.4 BGP Suppress FIB Pending Feature](#144-bgp-suppress-fib-pending-feature)
- [2. Implementation Stress Case](#2-implementation-stress-case)
  - [Task1: ExaBGP sends scale BGP routes](#task1-exabgp-sends-scale-bgp-routes)
  - [Task2: Dynamically generate a large number of routes](#task2-dynamically-generate-a-large-number-of-routes)
  - [Task3: Update `validate_route_states` and `validate_route_propagate` functions](#task3-update-validate_route_states-and-validate_route_propagate-functions)
  - [Task4: Generate test data only once](#task4-generate-test-data-only-once)
  - [Task5: Merge function case and stress case](#task5-merge-function-case-and-stress-case)
- [3. Future Plans](#3-future-plans)




# 1. Introduce Feature

## 1.1 Router receive a BGP route

![BGP receive route](https://github.com/goodluck68/Picture_Repo/blob/master/iShot_2023-10-23_19.15.05.png?raw=true)


1. **Apply Import Route Policy**
   
   When a router receive a BGP route, it passes through the import route policy which determines whether to accept, modify, or discard the route based on the  conditions.

2. **Place in BGP RIB**
   
   Once accepted, the route is placed in the BGP RIB. At this stage, the router has multiple routes to a destination if received from multiple neighbors.

3. **BGP Best Path Selection**
   
   This is where the router selects the best route to each destination. BGP uses a list of criteria (BGP path attributes, like AS_PATH, MED, etc.) to determine the best path.
   
4. **Insert into Global RIB**
   
   The best path selected by BGP is then inserted into the global RIB.

5. **FIB Population**
   
   The best routes from the global RIB are used to populate the FIB, which the router uses for actual packet forwarding.

6. **Apply Export Route Policy And Send to Neighbors**
   
   Before announcing routes to BGP neighbors, the routes are passed to the export route policy, which may modify or filter them. After that, the route is sent to BGP neighbors.



## 1.2 Routing Information Base & Forwarding Information Base

1. **Purpose**:
   - **RIB**: The Routing Information Base is the router's routing table. It contains all the route information the router learns via different routing protocols, static routes, OSPF routes, BGP routes. It's where routing algorithms determine the best path for a destination.
   - **FIB**: The Forwarding Information Base is directly related to forwarding traffic. It is derived from the RIB and is optimized for the rapid lookup required to forward packets. The FIB contains only the best routes from the RIB.

2. **Contents**:
   - **RIB**: Holds multiple paths to a destination if they are available. These paths include all attributes and metrics associated with those paths.
   - **FIB**: Only contains the best path to a destination, it focused on forwarding details like the next-hop address and the outgoing interface.

3. **Updates**:
   - **RIB**: Gets updated whenever there's a change in the network topology or if new routes are learned or existing routes change.
   - **FIB**: Is updated based on changes in the RIB. When the best path to a destination changes in the RIB, the FIB is updated accordingly.



## 1.3 Route Selection

1. **Weight check**
   
   Prefer the path with the highest `WEIGHT`. This attribute does not send to BGP neighbor

2. **Local preference check**
   
   Prefer the path with the highest `LOCAL_PREF`. Default value is 100.

3. **Local route check**
   
   Prefer the path that was locally originated via a `network`, `aggregate` or `redistributed` commands

4. **AS path length check**
   
   Prefer the path with the shortest `AS_PATH`.

5. **Origin check**
   
   Prefer the origin: IGP > INCOMPLETE
   - `network`: IGP
   - `redistribute`: Incomplete
   - `aggregate`: IGP
   
6. **MED check**
   
   Prefer the path with the lowest `MED`. Default value is 0.

7. **External check**
   
   Prefer EBGP over IBGP paths.

8. **IGP cost check**
   
   Prefer the path with the lowest IGP metric to the BGP next hop.

9.  **Multi-path check**
    
   If multi-pathing is enabled, then check whether the routes not yet distinguished in preference may be considered equal.



## 1.4 Important BGP knowledge

### 1.4.1 Loop Prevention

**Normal AS**
- **Within an AS**: `BGP Split Horizon Rule`

   In IBGP, if a router learns a route from one IBGP neighbor, it won't advertise that route to other IBGP neighbors. This rule exists to prevent loops.


- **Between AS**: `AS_PATH`

   When router sends BGP update to EBGP neighbor, the AS number is appended to the `AS_PATH` attribute of the route. If a router detects its own AS number in the `AS_PATH`, it recognizes the route as looping back and discards it.


**Route Reflectors**

- **Within Route Reflectors**: `ORIGINATOR_ID`

   When a route reflector forwards an IBGP update, it includes an optional BGP attribute called `ORIGINATOR_ID`. This attribute contains the router ID of the router that originated this route update. If a route reflector receives a route with an `ORIGINATOR_ID` that matches its own ID, it will discard the update to avoid a loop.


- **Between Route Reflectors**: `CLUSTER_LIST`

   `CLUSTER_LIST` is updated by the route reflector. This attribute is appended by the route reflector with its cluster-id. By default this is the BGP identifier. If a route reflector receives a `NLRI` with its cluster-id in the Cluster List attribute, the `NLRI` is discarded.


### 1.4.2 Difference between `network`/`redistribute`/`aggregate`

In routers, the `network`, `redistribute`, and `aggregate` commands can be used to generate BGP routes. However, their use cases is different, and the path attributes of the generated routes are different.

| Command        | Weight       | Origin       | Metric        |
| :---           | :----        | :----        | :----         |
| network        | 32768        | IGP          | 0             |
| redistribute   | 32768        | Incomplete   | IGP nexthop   |
| aggregate      | 32768        | IGP          | 0             |



### 1.4.3 BGP route aggregation attributes

1. **`Atomic_Aggregate`**
   
   This is a boolean attribute that indicates that a specific route in BGP has been aggregated, and that some information might have been lost due to that aggregation.

2. **`Aggregator`**

   This attribute provides information about the BGP speaker (AS number and IP address) that performed the route aggregation. It's used to identify where the aggregate take place

3. **`AS_SET`**
   
   When routes from multiple AS are aggregated, the AS numbers are stored in the `AS_SET`. This ensures loop prevention by maintaining a record of all AS included in the aggregate.

4. **`AS_SEQUENCE`**
   
   This represents the ordered list of AS numbers that a route advertisement has traversed, forming the conventional part of the `AS_PATH` attribute.


If the `AS_SET` attribute is used during route aggregation, path information is not lost. In this case, the `ATOMIC_AGGREGATE` attribute will no longer be used.
If the `AS_SET` attribute is not used during aggregation, the `ATOMIC_AGGREGATE` attribute must be used to inform routers along the path that this is an aggregated route and path information has been lost, to prevent routing loops.



## 1.4.4 BGP Suppress FIB Pending Feature

![BGP receive route](https://github.com/goodluck68/Picture_Repo/blob/master/iShot_2023-10-23_19.16.26.png?raw=true)

When router receives a BGP route from a peer, there are certain situations, such as when the hardware table is full, which can lead to routes not being installed in the FIB. However, the route can still be advertised to BGP neighbors. Subsequently, when neighboring routers send packets to router, the packets are dropped due to no route in the FIB, resulting in a routing blackhole.

The solution is to provide a configurable option to check for the FIB install status of the prefixes and advertise to peers if the prefixes are successfully installed in the FIB. The advertisement of the prefixes are suppressed if it is not installed in FIB.

`suppress-fib-pending` feature makes sure BGP routes are programmed first in hardware before using them for advertisement to the neighbors



# 2. Implementation Stress Case

## Task1: ExaBGP sends scale BGP routes

**Problem**: 

In the current script, routes are sent by executing commands on ExaBGP. In a stress case where we need to send 1000 routes, it's inefficient to loop the command execution 1000 times. So we need to find a method to send a large number of routes in a short time.

**Solution**: 

I submitted an issue in the ExaBGP project: [Issue #1187](https://github.com/Exa-Networks/exabgp/issues/1187) to ask this question. The provided solution was to use the `ANNOUNCE attribute next-hop self nlri 10.0.1.0/24 10.0.1.1/24 10.0.1.2/24` command for bulk route sending. Then, I updated the `generate_bgp_route_commands` function and modified the command to send BGP routes.

```python
def generate_bgp_route_commands(action, ip_routes):
    """
    Generate an exabgp command to announce or withdraw bgp routes using a given list of IP routes.

    Args:
    - action (str): Either "announce" or "withdraw"
    - ip_routes (list): A list of IP routes

    Returns:
    - string: A command string
    """
    if action not in ["announce", "withdraw"]:
        raise ValueError("Invalid action. Must be 'announce' or 'withdraw'.")

    # From https://github.com/Exa-Networks/exabgp/issues/1187, we can use
    # command 'announce attribute next-hop self nlri 10.0.0.1/24 10.0.0.2/24'
    # to announce multiple bgp routes with same attributes in one command
    command = f"{action} attribute next-hop self nlri {' '.join(ip_routes)}"
    logging.info("The exabgp command is: {}".format(command))

    return command
```


## Task2: Dynamically generate a large number of routes

**Problem**: 

In the existing script, the routes being used and the IP addresses during traffic test are defined within a constant. For stress testing, this approach is inefficient. This is the current implementation.

```python
# ipv4 route injection from T0
IP_ROUTE_LIST = [
    '91.0.1.0/24',
    '91.0.2.0/24'
]

# ipv6 route injection from T0
IPV6_ROUTE_LIST = [
    '1000:1001::/64',
    '1000:1002::/64'
]

TRAFFIC_DATA_FORWARD = [
    ("91.0.1.1", FORWARD),
    ("91.0.2.1", FORWARD),
    ("1000:1001::1", FORWARD),
    ("1000:1002::1", FORWARD)
]

TRAFFIC_DATA_DROP = [
    ("91.0.1.1", DROP),
    ("91.0.2.1", DROP),
    ("1000:1001::1", DROP),
    ("1000:1002::1", DROP),
]
```


**Solution**: 

Define new functions `generate_ip_routes` and `generate_traffic_data`. Both function test and stress test can use this method to generate routes, ensuring better scalability.

1. `generate_ip_routes` function: It takes the starting route address and the number of routes as inputs, dynamically generating the routes. 

```python
IP_ROUTE = '91.0.1.0/24'
IPV6_ROUTE = '1000:1001::/64'
ROUTE_COUNT = 2
BULK_ROUTE_COUNT = 1000

def generate_ip_routes(start_ip, count=1):
    """
    Generate a list of IP routes
    Example:
        input: start_ip = '10.0.1.0/24', count=5
        output: ['10.0.1.0/24', '10.0.2.0/24', '10.0.3.0/24', '10.0.4.0/24', '10.0.5.0/24']
    """
    route_list = [start_ip]
    for _ in range(count - 1):
        start_ip = ip_increment(start_ip)
        route_list.append(start_ip)
    return route_list


def ip_increment(ip_str):
    """
    Increment an IP subnet by 1.

    Example1:
        Input: 10.0.1.0/24
        Output: 10.0.2.0/24

    Example2:
        Input: 10.0.255.0/24
        Output: 10.1.0.0/24

    Example3:
        Input: 1000:1001:0:1::/64
        Output: 1000:1001:0:2::/64
    """
    # Convert the input string into an IP network object
    net = ipaddress.ip_network(ip_str, strict=False)

    # Calculate the next network address
    # Input: 10.0.1.0/24
    # "net.network_address" is the starting address of the current IP subnet, in this example is "10.0.1.0"
    # "net.num_addresses" is the number of ip addresses in the subnet, in this example is 256
    # So "10.0.2.0" is the next subnet
    next_net_addr = net.network_address + net.num_addresses

    # Convert the incremented address back to a string with the same netmask
    return f"{next_net_addr}/{net.prefixlen}"
```

1. `generate_traffic_data` function: It takes the generated route in previous steps as input, then get the first available IP address from the subnet as the traffic destination IP (The original case also uses the first available address in the subnet as the destination IP)

```python
def generate_traffic_data(route_list, action):
    """
    Generate traffic data list

    Example:
    Input: route_list=['91.0.1.0/24', '91.0.2.0/24'], action='FORWARD'
    Output: [
                ('91.0.1.1', 'FORWARD'),
                ('91.0.2.1', 'FORWARD')
            ]
    """
    traffic_data_list = []

    for route in route_list:
        first_ip = get_first_ip(route)
        traffic_data = (first_ip, action)
        traffic_data_list.append(traffic_data)

    return traffic_data_list


def get_first_ip(subnet):
    """
    Get the first usable IP from the subnet
    """
    # Use the subnet to generate an IP network object
    network = ipaddress.ip_network(subnet, strict=False)

    # hosts() method returns a generator that include all usable IPs in the subnet
    all_usable_ips = network.hosts()

    # Get the first usable IP from the generator
    first_ip = next(all_usable_ips)

    return str(first_ip)
```


## Task3: Update `validate_route_states` and `validate_route_propagate` functions

**Problem**:

Currently the `validate_route_states` and `validate_route_propagate` functions get routes from pre-defined constant. Now the routes have already generated dynamically, so need to update these two functions

```python
IP_ROUTE_LIST = [
    '91.0.1.0/24',
    '91.0.2.0/24'
]

IPV6_ROUTE_LIST = [
    '1000:1001::/64',
    '1000:1002::/64'
]

def validate_route_states(duthost, vrf=DEFAULT, check_point=QUEUED, action=ACTION_IN):
    """
    Verify ipv4 and ipv6 routes install status
    """
    for route in IP_ROUTE_LIST:
        check_route_install_status(duthost, route, vrf, IP_VER, check_point, action)
    for route in IPV6_ROUTE_LIST:
        check_route_install_status(duthost, route, vrf, IPV6_VER, check_point, action)
```

**Solution**:

Update the functions `validate_route_states` and `validate_route_propagate` to read routes from dynamically generated data, so that it is also applicable to a large number of routes

1. `validate_route_states` function: Add a parameter `ip_routes` to pass route info

```python
def validate_route_states(duthost, ip_routes, vrf=DEFAULT, check_point=QUEUED, action=ACTION_IN):
    """
    Verify ipv4 and ipv6 routes install status
    """
    for route in ip_routes:
        # IPv4 address has a ".", IPv6 address has a ":", use this to determine the IP version
        ip_ver = IP_VER if "." in route else IPV6_VER
        check_route_install_status(duthost, route, vrf, ip_ver, check_point, action)
```

2. `validate_route_propagate` function: Add parameters `ipv4_route_list` and `ipv6_route_list` to pass route info

```python
def validate_route_propagate(duthost, tbinfo, vrf=DEFAULT, exist=True, ipv4_route_list=None, ipv6_route_list=None):
    """
    Verify ipv4 and ipv6 route propagate status
    """
    if not ipv4_route_list and not ipv6_route_list:
        logging.error("Both ipv4_route_list and ipv6_route_list are empty")
        return

    t2_vm = get_vm_name(tbinfo)
    bgp_neighbor_v4, bgp_neighbor_v6 = get_bgp_neighbor_ip(duthost, t2_vm, vrf)

    if ipv4_route_list:
        for route in ipv4_route_list:
            validate_route_propagate_status(duthost, route, bgp_neighbor_v4, vrf, exist=exist)

    if ipv6_route_list:
        for route in ipv6_route_list:
            validate_route_propagate_status(duthost, route, bgp_neighbor_v6, vrf, ip_ver=IPV6_VER, exist=exist)
```


## Task4: Generate test data only once

**Problem**:

When I initially to write the case, the steps to generate routes and traffic were executed internally within the script. With `@pytest.mark.parametrize("vrf_type", ["default", "Vrf1"])`, the script runs twice, leading to data fetching duplication.

```python
@pytest.mark.parametrize("vrf_type", VRF_TYPES)
def test_bgp_route_with_suppress(duthost, tbinfo, nbrhosts, ptfadapter, localhost, restore_bgp_suppress_fib,
                                 get_exabgp_ptf_ports, vrf_type, request):
    try:
        if vrf_type == USER_DEFINED_VRF:
            with allure.step("Configure user defined vrf"):
                setup_vrf(duthost, nbrhosts, tbinfo)

        with allure.step("Prepare needed parameters"):
            router_mac = duthost.facts["router_mac"]
            mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
            ptf_ip = tbinfo['ptf_ip']
            exabgp_port, ptf_recv_port, exabgp_port_v6, ptf_recv_port_v6 = get_exabgp_ptf_ports
            recv_port = {
                4: ptf_recv_port,
                6: ptf_recv_port_v6
            }
            # Generate test route dynamically, input a start route and route count to generate a list of routes
            # So that the functional test and stress test can use same way to generate routes
            # TBD: other three cases also need to add this content
            ip_routes_ipv4 = generate_ip_routes(IP_ROUTE, count=ROUTE_COUNT)
            ip_routes_ipv6 = generate_ip_routes(IPV6_ROUTE, count=ROUTE_COUNT)

            # Generate traffic data dynamically, the format is same as current constant
            # TRAFFIC_DATA_DROP and TRAFFIC_DATA_FORWARD
            # For example:
            # Input ['91.0.1.0/24', '91.0.2.0/24']
            # Output [('91.0.1.1', 'FORWARD'), ('91.0.2.1', 'FORWARD')]
            traffic_data_ipv4_drop = generate_traffic_data(ip_routes_ipv4, DROP)
            traffic_data_ipv6_drop = generate_traffic_data(ip_routes_ipv6, DROP)
            traffic_data_ipv4_forward = generate_traffic_data(ip_routes_ipv4, FORWARD)
            traffic_data_ipv6_forward = generate_traffic_data(ip_routes_ipv6, FORWARD)

```


**Solution**:

Introduce a pytest fixture to generate test data externally and set `scope="module"`. This ensures that each test file only needs to generate test data once, and all test cases within that file can use this data.

```python
IP_ROUTE = '91.0.1.0/24'
IPV6_ROUTE = '1000:1001::/64'
ROUTE_COUNT = 2
BULK_ROUTE_COUNT = 1000
DROP = "DROP"
FORWARD = "FORWARD"

@pytest.fixture(scope="module")
def generate_route_and_traffic_data():
    """
    Pytest fixture for generating route and traffic data

    1. Generate routes for ExaBGP to send to DUT
    2. Generate the destination IP addresses based on the generated routes, which is used to test traffic

    Example:
    route_and_traffic_data = {
            'ip_routes_ipv4': ['91.0.1.0/24', '91.0.2.0/24'],
            'ip_routes_ipv6': ['1000:1001:0:1::/64', '1000:1001:0:2::/64'],
            'traffic_data_ipv4_drop': [('91.0.1.0/24', 'DROP'), ('91.0.2.0/24', 'DROP')],
            'traffic_data_ipv6_drop': [('1000:1001:0:1::/64', 'DROP'), ('1000:1001:0:2::/64', 'DROP')],
            'traffic_data_ipv4_forward': [('91.0.1.0/24', 'FORWARD'), ('91.0.2.0/24', 'FORWARD')],
            'traffic_data_ipv6_forward': [('1000:1001:0:1::/64', 'FORWARD'), ('1000:1001:0:2::/64', 'FORWARD')]
        }
    """

    # Generate test route dynamically for function tests
    ip_routes_ipv4 = generate_ip_routes(IP_ROUTE, count=ROUTE_COUNT)
    ip_routes_ipv6 = generate_ip_routes(IPV6_ROUTE, count=ROUTE_COUNT)

    # Generate test route dynamically for stress tests
    ip_routes_ipv4_stress = generate_ip_routes(IP_ROUTE, count=BULK_ROUTE_COUNT)
    ip_routes_ipv6_stress = generate_ip_routes(IPV6_ROUTE, count=BULK_ROUTE_COUNT)

    route_and_traffic_data = {
        "function": {
            "ip_routes_ipv4": ip_routes_ipv4,
            "ip_routes_ipv6": ip_routes_ipv6,
            "traffic_data_ipv4_drop": generate_traffic_data(ip_routes_ipv4, DROP),
            "traffic_data_ipv6_drop": generate_traffic_data(ip_routes_ipv6, DROP),
            "traffic_data_ipv4_forward": generate_traffic_data(ip_routes_ipv4, FORWARD),
            "traffic_data_ipv6_forward": generate_traffic_data(ip_routes_ipv6, FORWARD)
        },
        "stress": {
            "ip_routes_ipv4": ip_routes_ipv4_stress,
            "ip_routes_ipv6": ip_routes_ipv6_stress,
            "traffic_data_ipv4_drop": generate_traffic_data(ip_routes_ipv4_stress, DROP),
            "traffic_data_ipv6_drop": generate_traffic_data(ip_routes_ipv6_stress, DROP),
            "traffic_data_ipv4_forward": generate_traffic_data(ip_routes_ipv4_stress, FORWARD),
            "traffic_data_ipv6_forward": generate_traffic_data(ip_routes_ipv6_stress, FORWARD)
        }
    }

    return route_and_traffic_data
```

The testcase call `get_test_data` function, it will return the required data based on the expected `test_type`
```python
def get_test_data(generate_route_and_traffic_data, test_type, include_forward=True, include_drop=True):
    """
    Get test data based on the test type.

    Parameters:
        generate_route_and_traffic_data: A dict containing routes and traffic data.
        test_type: The type of the test ("function" or "stress").
        include_forward: Whether to include forward traffic data.
        include_drop: Whether to include drop traffic data.

    Returns:
        tuple: A tuple containing selected routes and traffic data.

    Example:
    1. Retrieving all data:
        (ip_routes_ipv4, ip_routes_ipv6, traffic_data_ipv4_forward, traffic_data_ipv6_forward,
         traffic_data_ipv4_drop, traffic_data_ipv6_drop) = get_test_data(generate_route_and_traffic_data, "function")

    2. Retrieving only routes and forward data:
        (ip_routes_ipv4, ip_routes_ipv6, traffic_data_ipv4_forward, traffic_data_ipv6_forward) =
            get_test_data(generate_route_and_traffic_data, "function", include_drop=False)
    """

    test_data = generate_route_and_traffic_data[test_type]
    ip_routes_ipv4 = test_data["ip_routes_ipv4"]
    ip_routes_ipv6 = test_data["ip_routes_ipv6"]
    results = [ip_routes_ipv4, ip_routes_ipv6]

    # Include forward traffic data if requested
    if include_forward:
        traffic_data_ipv4_forward = test_data["traffic_data_ipv4_forward"]
        traffic_data_ipv6_forward = test_data["traffic_data_ipv6_forward"]
        results.extend([traffic_data_ipv4_forward, traffic_data_ipv6_forward])

    # Include drop traffic data if requested
    if include_drop:
        traffic_data_ipv4_drop = test_data["traffic_data_ipv4_drop"]
        traffic_data_ipv6_drop = test_data["traffic_data_ipv6_drop"]
        results.extend([traffic_data_ipv4_drop, traffic_data_ipv6_drop])

    return tuple(results)


@pytest.mark.parametrize("vrf_type", VRF_TYPES)
@pytest.mark.parametrize("test_type", TEST_TYPES)
def test_bgp_route_with_suppress(duthost, tbinfo, nbrhosts, ptfadapter, localhost, restore_bgp_suppress_fib,
                                 get_exabgp_ptf_ports, vrf_type, request, generate_route_and_traffic_data, test_type):
    # Get route and traffic data for testing
    (ip_routes_ipv4, ip_routes_ipv6,
     traffic_data_ipv4_forward, traffic_data_ipv6_forward,
     traffic_data_ipv4_drop, traffic_data_ipv6_drop) = get_test_data(generate_route_and_traffic_data, test_type)
```


## Task5: Merge function case and stress case

**Problem**:

Many test steps in the functional test case `test_bgp_route_with_suppress` are the same as those in the stress test case. These two cases can be merged.

**Solution**:

Add a parameter `test_type` to control the test type, and use `@pytest.mark.parametrize("test_type", ["function", "stress"])` to pass the parameters to the script. This way the script can cover functional testing and stress testing

```python
TEST_TYPES = ["function", "stress"]
REPEAT_TIMES = 10

@pytest.mark.parametrize("vrf_type", VRF_TYPES)
@pytest.mark.parametrize("test_type", TEST_TYPES)
def test_bgp_route_with_suppress(duthost, tbinfo, nbrhosts, ptfadapter, localhost, restore_bgp_suppress_fib,
                                 get_exabgp_ptf_ports, vrf_type, request, generate_route_and_traffic_data, test_type):
    # Get route and traffic data for testing
    (ip_routes_ipv4, ip_routes_ipv6,
     traffic_data_ipv4_forward, traffic_data_ipv6_forward,
     traffic_data_ipv4_drop, traffic_data_ipv6_drop) = get_test_data(generate_route_and_traffic_data, test_type)

    ...

        with allure.step("Suspend orchagent process to simulate a route install delay"):
            operate_orchagent(duthost)

        # Announce and withdraw BGP routes multiple times
        if test_type == "stress":
            for _ in range(REPEAT_TIMES):
                with allure.step("Announce BGP ipv4 and ipv6 routes to DUT from T0 VM by ExaBGP"):
                    install_route_from_exabgp(ANNOUNCE, ptf_ip, ip_routes_ipv4 + ip_routes_ipv6, exabgp_port, exabgp_port_v6)

                with allure.step("Validate announced BGP ipv4 and ipv6 routes are in {} state".format(QUEUED)):
                    validate_route_states(duthost, ip_routes_ipv4 + ip_routes_ipv6, vrf_type)

                with allure.step("Validate BGP ipv4 and ipv6 routes are not announced to T2 VM peer"):
                    validate_route_propagate(duthost, tbinfo, vrf_type, exist=False, ipv4_route_list=ip_routes_ipv4, ipv6_route_list=ip_routes_ipv6)

                with allure.step("Withdraw BGP ipv4 and ipv6 routes to DUT from T0 VM by ExaBGP"):
                    install_route_from_exabgp(WITHDRAW, ptf_ip, ip_routes_ipv4 + ip_routes_ipv6, exabgp_port, exabgp_port_v6)

        with allure.step("Announce BGP ipv4 and ipv6 routes to DUT from T0 VM by ExaBGP"):
            install_route_from_exabgp(ANNOUNCE, ptf_ip, ip_routes_ipv4 + ip_routes_ipv6, exabgp_port, exabgp_port_v6)
```


# 3. Future Plans
1. Learn how to generate a test topology and how to setup a testbed.
2. Extract the same function defined in different files and put them into a common file
   
   The function of sending routes is defined in several BGP test files. We can put this common function into a public file, and then all scripts call this function, which is more convenient for maintenance.

For example:
- `test_bgp_sentinel.py`

```python
def announce_route(ptfip, neighbor, route, nexthop, port, community):
    change_route("announce", ptfip, neighbor, route, nexthop, port, community)
```

- `test_bgp_bbr.py`
```python
def announce_routes(routes):
    logger.info('Announce routes {} to the first T0'.format(str(routes)))
    for route in routes:
        bbr_routes.append(route)
        if ipaddress.IPNetwork(route.prefix).version == 4:
            update_routes('announce', ptfhost.mgmt_ip, tor1_exabgp_port, route)
        else:
            update_routes('announce', ptfhost.mgmt_ip, tor1_exabgp_port_v6, route)
    time.sleep(3)
```