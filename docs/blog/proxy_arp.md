---
title: Openstack DVR Code Analysis
date: 2018-10-27
description:
    Analyze openstack neutron source code in order to find out how is DVR implemented. Traffic from VM without any floating ip will still flow through a centralized gateway node to access internet resource; while vm with floating ip could directly goes outside from the compute node.
---

# RANDOM THOUGHT ON PROXY ARP

Openstack neutron `dvr` mode relies on proxy arp to provide floating ip service. So I would like to dig in and find out how it implements both in terms of linux and neutron source code. By understanding the basics, it will do great help to understand what is going on under the hood.

## DEMO

In this section, I would like to present you how to do a demo proxy arp in a Unbuntu 16.04 virtual machine. For simplicity I use a network namespace to offer a network isolation. I admit to feel uncomfortable with iptables but nevermind it is not necessary unless you want to really **talk** to the proxied nic.

### PREPARE SYSTEM CONF

```bash
# sysctl could be used to check system configurations
# make sure that following values to be 1
sysctl net.ipv4.conf.${NIC}.proxy_arp
sysctl net.ipv4.ip_forward

# if above is not 1
# then manually set it to 1
# ssyctl -w net.ipv4.conf.all.proxy_arp=1
sysctl -w net.ipv4.conf.${NIC}.proxy_arp=1
sysctl -w net.ipv4.ip_forward=1
```

### NETWORK BIRDVIEW

```raw
# ----------              -----------
# |        |              |         |
# | net 1  |   <------>   |  net 2  |
# | proxy  |              |  netns  |
# |        |              |         |
# ----------              -----------
```

### CREATE NETNS & VETH PAIR

```bash
ip netns add ${NS_NAME}
ip link add ${VETH0} type veth peer name ${VETH1}
ip link set ${VETH1} netns ${NS_NAME}

# give them ip addresses
ip addr add ${VETH0_CIRD} dev ${VETH0}
ip link set ${VETH0_CIRD} up
ip netns exec ${NS_NAME} ip addr add ${VETH1_CIRD} dev ${VETH1}
ip netns exec ${NS_NAME} ip link set ${VETH1} up

# test connectivity by ping
ip netns exec ${NS_NAME} ping ${VETH0_ADDR}
```

### SETUP PROXY ARP

```bash
ip route add to ${PROXIED_IPADDR} via ${ANOTHER_IPADDR_ON_VM}

# try arping in another namespace
# install arping if it is not present
ip netns exec ${NS_NAME} arping ${VETH0}
```

### PROXY ARP REFERENCES

Threads I've read

* [a good reference on dvr implementation](http://www.cnblogs.com/sammyliu/p/4713562.html)
* [mostly refered to article on dvr and ovs](https://assafmuller.com/2015/04/15/distributed-virtual-routing-floating-ips/)
* [set up proxy arp](https://infosec-neo.blogspot.com/2007/07/how-to-implement-proxy-arp-on-linux-box.html)
* [how to enable/disable proxy arp in linux](http://www.linuxproblem.org/art_8.html)

## IPTABLES USAGES

## NORTH-SOUTH TRAFFIC

## NEUTRON CODE ANALYSIS

### ML2 PLUGIN (EXTENSION)

Resource (resource map) are extended by extension plugins.

* neutron manager initialize, `_load_service_plugins`, namespace: `neutron.service_plugins`.
* `L3_ROUTER_NAT` connects extension with service plugin; `neutron.services.l3_router.l3_router_plugin.L3RouterPlugin#get_plugin_type`
* ExtensionManager loads extensions (default: neutron/extension)
* Extension(ExtensionDesriptor) got method `get_resource` which will return a collection of object having both controller and plugin etc.
* l3 agent service callbacks are registerd at `neutron.services.l3_router.l3_router_plugin.L3RouterPlugin#__init__`.
* fip port is created here `neutron.agent.l3.dvr_fip_ns.FipNamespace#_create_gateway_port`, `dvr_fip_ns.py` implements specific fip namespace.
* router updated notification is received & responsed `neutron.agent.l3.agent.L3NATAgent#_process_router_update`.
* process router with `neutron.agent.l3.agent.L3NATAgent#_process_router_if_compatible` if it does not exis or `self.router_info` is not intialized
* For south-north traffic, traffic originated from VM will first be sent to **local router**, and then go all the way to **snat namespace**; the reply packet will first hit **snat**, then dvr router on **network node**, and finally return to VM. So basically packet will go throught different path which could be easily verified by `tcpdump`.
* gratuitous arp for updating arp tables of on-link devices.

**Router** and **Floating** are all handled by service plugin named `L3RouterPlugin` and extension named `L3` in `extensions/l3.py` whereas extension extends rest api with extra controllers and service plugin offers method for the specific controller. How each extension is loaded depends on which neutron frontend framework is adopted, there are two frameworks exist, one for python paste and another one is for pecan. It is believed that the latter is going to replace legacy one, so I'm going to talk about api chain with the latter in the following chapter; but both of them share significant similiarities so analysis here should go fit another quite easily.

#### INITIALIZATION PROCESS

Initialization takes place at `neutron.pecan_wsgi.startup.initialize_all`. It first loads ml2 plugin which handles networks, subnets and ports. Then it will load all the extensions,

```python
def initalize_all():
    # skip code block
    resources = ext_mgr.get_resources()
```

Here resources could be interpreted as neutron managed objects, such as network, router, etc. More specifically it is list concatenation of return from `neutron_lib.api.extensions.ExtensionDescriptor#get_resources`. Then code traverses all the resources (except default) and register controllers in `NeutronManager`. Until now, controllers are registered and related requests should be handled properly.

#### REST API ENTRANCE

Neutron has a unique flavor of defining method name as a combination of **action** (update, create) and **resource** (network, router), remember the fact that plugins are actual executor for a controller, it then become an obvious guess that floating ip creation method could be found in `L3RouterPlugin`. It is actually there with name `create_floatingip`. But keep in mind that it is possible that above guess is not correct, because besides typical naming convention, an action map could also be passed in to handle non-canonical request. Go to `get_resources` method and checkout how **action map** is initialized there.

```python
@resource_extend.has_resource_extenders
class L3RouterPlugin(service_base.ServicePluginBase,
                     common_db_mixin.CommonDbMixin,
                     extraroute_db.ExtraRoute_db_mixin,
                     l3_hamode_db.L3_HA_NAT_db_mixin,
                     l3_gwmode_db.L3_NAT_db_mixin,
                     l3_dvr_ha_scheduler_db.L3_DVR_HA_scheduler_db_mixin,
                     dns_db.DNSDbMixin):
    def create_floatingip(self, context, floatingip):
        """Create floating IP.

        :param context: Neutron request context
        :param floatingip: data for the floating IP being created
        :returns: A floating IP object on success

        As the l3 router plugin asynchronously creates floating IPs
        leveraging the l3 agent, the initial status for the floating
        IP object will be DOWN.
        """
        return super(L3RouterPlugin, self).create_floatingip(
            context, floatingip,
            initial_status=n_const.FLOATINGIP_STATUS_DOWN)


class L3_NAT_db_mixin(L3_NAT_dbonly_mixin, L3RpcNotifierMixin):
    def create_floatingip(self, context, floatingip,
            initial_status=constants.FLOATINGIP_STATUS_ACTIVE):
        floatingip_dict = super(L3_NAT_db_mixin, self).create_floatingip(
            context, floatingip, initial_status)
        router_id = floatingip_dict['router_id']
        self.notify_router_updated(context, router_id, 'create_floatingip')
        return floatingip_dict


@registry.has_registry_receivers
class L3_NAT_dbonly_mixin(l3.RouterPluginBase,
                          base_services.WorkerBase,
                          st_attr.StandardAttrDescriptionMixin):
    """Mixin class to add L3/NAT router methods to db_base_plugin_v2."""
    @db_api.retry_if_session_inactive()
    def create_floatingip(self, context, floatingip,
            initial_status=constants.FLOATINGIP_STATUS_ACTIVE):
        return self._create_floatingip(context, floatingip, initial_status)

    def _create_floatingip(self, context, floatingip,
        initial_status=constants.FLOATINGIP_STATUS_ACTIVE):
        # create db entry

        # callbackup, but for now callback is not registered
        registry.notify(resources.FLOATING_IP,
                events.AFTER_UPDATE,
                self._update_fip_assoc, **assoc_result)
```

As above code shows, l3 router plugin handles db entry creation (floating ip) and agent notificiation (instead of a rpc call/cast). The logic is written in `neutron.db.l3_db.L3_NAT_dbonly_mixin#_create_floatingip`, it will test if network is external or contains a subnet, if succeeds, then a port with external ip is created. After port has been created, floating ip entry will have information and will be ready to create a new db record.

So what is clear from above snippet is that **real port** is created by **l3-agent** from notifications. So next step will be analyzing how **l3-agent** works. The notification is `routers_updated` which action is secretly dropped by `neutron.api.rpc.agentnotifiers.l3_rpc_agent_api.L3AgentNotifyAPI#_agent_notification_arp`, but it does not matter.

#### L3-AGENT HANDLES NOTIFICATION

By design rpc calls will be handled by method of the same name here it is `routers_updated`, this method is nowhere but `neutron.agent.l3.agent.L3NATAgent#routers_updated`, noticing that `L3NATAgentWithStateReport`, which is a manager class, is a sub class of `L3NATAgent`

```python
class L3NATAgent(ha.AgentMixin,
                 dvr.AgentMixin,
                 manager.Manager):
    """Manager for L3NatAgent"""

    def routers_updated(self, context, routers):
        """Deal with routers modification and creation RPC message."""
        if routers:
            # This is needed for backward compatibility
            if isinstance(routers[0], dict):
                routers = [router['id'] for router in routers]
            for id in routers:
                update = queue.RouterUpdate(id, queue.PRIORITY_RPC)
                self._queue.add(update)

    def after_start(self):
        eventlet.spawn_n(self._process_routers_loop)
        LOG.info("L3 agent started")


@profiler.trace_cls("l3-agent")
class L3NATAgent(ha.AgentMixin,
                 dvr.AgentMixin,
                 manager.Manager):

    # spawn eventlet to handle router update uqueue
    def _process_routers_loop(self):
        LOG.debug("Starting _process_routers_loop")
        pool = eventlet.GreenPool(size=8)
        while True:
            pool.spawn_n(self._process_router_update)

    # process candidates
    def _process_router_update(self):
        for rp, update in self._queue.each_update_to_next_router():
            router = update.router
            if update.action != queue.DELETE_ROUTER and not router:
                try:
                    update.timestamp = timeutils.utcnow()
                    # initialize router object by given id
                    routers = self.plugin_rpc.get_routers(self.context,
                                                          [update.id])
                except Exception:
                    continue

                if routers:
                    router = routers[0]

            try:
                # process router if it should be handled locally
                self._process_router_if_compatible(router)
            except Exception as e:
                continue

    def _process_router_if_compatible(self, router):

        # If target_ex_net_id and ex_net_id are set they must be equal
        target_ex_net_id = self._fetch_external_net_id()
        if (target_ex_net_id and ex_net_id and ex_net_id != target_ex_net_id):
            # Double check that our single external_net_id has not changed
            # by forcing a check by RPC.
            if ex_net_id != self._fetch_external_net_id(force=True):
                raise n_exc.RouterNotCompatibleWithAgent(
                    router_id=router['id'])

        if router['id'] not in self.router_info:
            # If router does not exists or service has been restarted
            # reinitialize instance
            self._process_added_router(router)
        else:
            # if router already there, then update it directly
            self._process_updated_router(router)


    # update router
    def _process_updated_router(self, router):
        ri = self.router_info[router['id']]
        is_dvr_only_agent = (self.conf.agent_mode in
                            [lib_const.L3_AGENT_MODE_DVR,
                            l3_constants.L3_AGENT_MODE_DVR_NO_EXTERNAL])
        is_ha_router = getattr(ri, 'ha_state', None) is not None
        # For HA routers check that DB state matches actual state
        if router.get('ha') and not is_dvr_only_agent and is_ha_router:
            self.check_ha_state_for_router(
                router['id'], router.get(l3_constants.HA_ROUTER_STATE_KEY))
        ri.router = router
        # notfiy that router is to be updated
        registry.notify(resources.ROUTER, events.BEFORE_UPDATE,
                        self, router=ri)

        # there are two types of dvr rotuers: dvr, dvr_snat
        ri.process()

        # notify router has finished updating
        registry.notify(resources.ROUTER, events.AFTER_UPDATE, self, router=ri)
        self.l3_ext_manager.update_router(self.context, router)


# neutron.service.Service
class Service(n_rpc.Service):
    def start(self):
        self.manager.init_host()
        super(Service, self).start()
        if self.report_interval:
            pulse = loopingcall.FixedIntervalLoopingCall(self.report_state)
            pulse.start(interval=self.report_interval,
                        initial_delay=self.report_interval)
            self.timers.append(pulse)

        if self.periodic_interval:
            if self.periodic_fuzzy_delay:
                initial_delay = random.randint(0, self.periodic_fuzzy_delay)
            else:
                initial_delay = None

            periodic = loopingcall.FixedIntervalLoopingCall(
                self.periodic_tasks)
            periodic.start(interval=self.periodic_interval,
                           initial_delay=initial_delay)
            self.timers.append(periodic)

        # -----------------------------------
        # going to start those eventlet pools
        self.manager.after_start()
```

The code till triggers `process` method is pretty complex. There are several things to keep in mind

* Manager (L3NATAgent etc) handles a queued router update notification, and consume it by spawning coroutine in greenlet pool. This task is started by `Manager.after_start` inside `Service.start` method.
* `router_info` object will be created (because it is saved in memory) every time `l3-agent` is restarted and `_process_added_router` will be triggered if `router_info[key]` is empty.

#### CORE

In dvr mode, a router could be further catogrized into at least three modes: **dvr snat**, **dvr local**, **dvr edge**. Generally speaking **dvr snat** is used for snat flow on network node; **dvr local** typically resides on compute nodes; **dvr edge** locates on compute node but not going to handle out-going traffic flows (so floating ip should not be associated on this node). So now it is clear we are interesting in implementation of **dvr local** which is what we have in production.

There are two types of routers, one is `dvr`, ther other is `dvr_snat`. Their implmentations are `DvrLocalRouter` and `DvrEdgeRouter` respectively. DvrLocalRouter is responsible for routing traffic on compute nodes, while DvrEdgeRouter is a NAT gateway.

```python
# handle router on compute node
class DvrLocalRouter(dvr_router_base.DvrRouterBase):

    # entrance
    def process(self):
        ex_gw_port = self.get_ex_gw_port()
        if ex_gw_port:
            # agent is 'L3NATAgentWithStateReport' itself
            # fip name is created from network_id
            self.fip_ns = self.agent.get_fip_ns(ex_gw_port['network_id'])

            # scan port in fip namespace and remove those staled ips
            self.fip_ns.scan_fip_ports(self)

        super(DvrLocalRouter, self).process()

    # override parent class method
    def process_external(self):
        # this is a dvr router
        if self.agent_conf.agent_mode != (
            n_const.L3_AGENT_MODE_DVR_NO_EXTERNAL):
            ex_gw_port = self.get_ex_gw_port()
            if ex_gw_port:
                # make sure fg-xxx tap device exists
                self.create_dvr_external_gateway_on_agent(ex_gw_port)
                # make sure qrouter & fip are connected
                self.connect_rtr_2_fip()
        super(DvrLocalRouter, self).process_external()

    def create_dvr_external_gateway_on_agent(self, ex_gw_port):
        fip_agent_port = self.get_floating_agent_gw_interface(
            ex_gw_port['network_id'])
        if not fip_agent_port:
            fip_agent_port = self.agent.plugin_rpc.get_agent_gateway_port(
                self.agent.context, ex_gw_port['network_id'])
            LOG.debug("FloatingIP agent gateway port received from the "
                      "plugin: %s", fip_agent_port)
        self.fip_ns.create_or_update_gateway_port(fip_agent_port)

    def get_router_cidrs(self, device):
        """As no floatingip will be set on the rfp device. Get floatingip from
        the route of fip namespace.
        """
        if not self.fip_ns:
            return set()

        fip_ns_name = self.fip_ns.get_name()
        fip_2_rtr_name = self.fip_ns.get_int_device_name(self.router_id)
        device = ip_lib.IPDevice(fip_2_rtr_name, namespace=fip_ns_name)
        if not device.exists():
            return set()

        if self.rtr_fip_subnet is None:
            self.rtr_fip_subnet = self.fip_ns.local_subnets.allocate(
                self.router_id)
        rtr_2_fip, _fip_2_rtr = self.rtr_fip_subnet.get_pair()
        exist_routes = device.route.list_routes(
            lib_constants.IP_VERSION_4, via=str(rtr_2_fip.ip))
        return {common_utils.ip_to_cidr(route['cidr'])
                for route in exist_routes}

    def add_floating_ip(self, fip, interface_name, device):
        # Special Handling for DVR - update FIP namespace
        ip_cidr = common_utils.ip_to_cidr(fip['floating_ip_address'])
        return self.floating_ip_added_dist(fip, ip_cidr)

    def floating_ip_added_dist(self, fip, fip_cidr):
        """Add floating IP to respective namespace based on agent mode."""
        if fip.get(n_const.DVR_SNAT_BOUND):
            floating_ip_status = self.add_centralized_floatingip(fip, fip_cidr)
            if floating_ip_status == lib_constants.FLOATINGIP_STATUS_ACTIVE:
                self.centralized_floatingips_set.add(fip_cidr)
            return floating_ip_status
        if not self._check_if_floatingip_bound_to_host(fip):
            return
        floating_ip = fip['floating_ip_address']
        fixed_ip = fip['fixed_ip_address']

        # add rule for routing fip traffic backup to qrouter-xxx
        self._add_floating_ip_rule(floating_ip, fixed_ip)
        fip_2_rtr_name = self.fip_ns.get_int_device_name(self.router_id)
        #Add routing rule in fip namespace
        fip_ns_name = self.fip_ns.get_name()
        if self.rtr_fip_subnet is None:
            self.rtr_fip_subnet = self.fip_ns.local_subnets.allocate(
                self.router_id)
        rtr_2_fip, __ = self.rtr_fip_subnet.get_pair()
        device = ip_lib.IPDevice(fip_2_rtr_name, namespace=fip_ns_name)

        # add this route for proxy arp purpose
        # when fip namespace is created, net.ipv4.conf.xxx.proxy_arp will 
        # be set to 1
        device.route.add_route(fip_cidr, str(rtr_2_fip.ip))
```

```python
# handles snat & iptables
class DvrEdgeRouter(dvr_local_router.DvrLocalRouter):
    def external_gateway_added(self, ex_gw_port, interface_name):
        super(DvrEdgeRouter, self).external_gateway_added(
            ex_gw_port, interface_name)
        if self._is_this_snat_host():
            self._create_dvr_gateway(ex_gw_port, interface_name)
            # NOTE: When a router is created without a gateway the routes get
            # added to the router namespace, but if we wanted to populate
            # the same routes to the snat namespace after the gateway port
            # is added, we need to call routes_updated here.
            self.routes_updated([], self.router['routes'])
        elif self.snat_namespace.exists():
            # This is the case where the snat was moved manually or
            # rescheduled to a different agent when the agent was dead.
            LOG.debug("SNAT was moved or rescheduled to a different host "
                      "and does not match with the current host. This is "
                      "a stale namespace %s and will be cleared from the "
                      "current dvr_snat host.", self.snat_namespace.name)
            self.external_gateway_removed(ex_gw_port, interface_name)

    def _create_dvr_gateway(self, ex_gw_port, gw_interface_name):
        snat_ns = self._create_snat_namespace()
        # connect snat_ports to br_int from SNAT namespace
        for port in self.get_snat_interfaces():
            self._plug_snat_port(port)
        self._external_gateway_added(ex_gw_port, gw_interface_name,
                                     snat_ns.name, preserve_ips=[])
        self.snat_iptables_manager = iptables_manager.IptablesManager(
            namespace=snat_ns.name,
            use_ipv6=self.use_ipv6)

        self._initialize_address_scope_iptables(self.snat_iptables_manager)

    def _plug_snat_port(self, port):
        interface_name = self._get_snat_int_device_name(port['id'])
        self._internal_network_added(
            self.snat_namespace.name, port['network_id'],
            port['id'], port['fixed_ips'],
            port['mac_address'], interface_name,
            lib_constants.SNAT_INT_DEV_PREFIX,
            mtu=port.get('mtu'))
```

```python
# base class
class RouterInfo(object):
    def process_external(self):
        fip_statuses = {}
        try:
            with self.iptables_manager.defer_apply():
                ex_gw_port = self.get_ex_gw_port()
                self._process_external_gateway(ex_gw_port)
                if not ex_gw_port:
                    return

                # Process SNAT/DNAT rules and addresses for floating IPs
                self.process_snat_dnat_for_fip()

            # Once NAT rules for floating IPs are safely in place
            # configure their addresses on the external gateway port
            interface_name = self.get_external_device_interface_name(
                ex_gw_port)
            fip_statuses = self.configure_fip_addresses(interface_name)

    def configure_fip_addresses(self, interface_name):
        try:
            return self.process_floating_ip_addresses(interface_name)
        except Exception:
            # TODO(salv-orlando): Less broad catching
            msg = _('L3 agent failure to setup floating IPs')
            LOG.exception(msg)
            raise n_exc.FloatingIpSetupException(msg)

    def create_or_update_gateway_port(self, agent_gateway_port):
        interface_name = self.get_ext_device_name(agent_gateway_port['id'])

        # The lock is used to make sure another thread doesn't call to
        # update the gateway port before we are done initializing things.
        with self._fip_port_lock(interface_name):
            is_first = self.subscribe(agent_gateway_port['network_id'])
            if is_first:
                self._create_gateway_port(agent_gateway_port, interface_name)
            # skip

    def _create_gateway_port(self, ex_gw_port, interface_name):
        """Create namespace, request port creationg from Plugin,
           then configure Floating IP gateway port.
        """
        self.create()

        LOG.debug("DVR: adding gateway interface: %s", interface_name)
        ns_name = self.get_name()
        self.driver.plug(ex_gw_port['network_id'],
                         ex_gw_port['id'],
                         interface_name,
                         ex_gw_port['mac_address'],
                         bridge=self.agent_conf.external_network_bridge,
                         namespace=ns_name,
                         prefix=FIP_EXT_DEV_PREFIX,
                         mtu=ex_gw_port.get('mtu'))

        # Remove stale fg devices
        ip_wrapper = ip_lib.IPWrapper(namespace=ns_name)
        devices = ip_wrapper.get_devices()
        for device in devices:
            name = device.name
            if name.startswith(FIP_EXT_DEV_PREFIX) and name != interface_name:
                LOG.debug('DVR: unplug: %s', name)
                ext_net_bridge = self.agent_conf.external_network_bridge
                self.driver.unplug(name,
                                   bridge=ext_net_bridge,
                                   namespace=ns_name,
                                   prefix=FIP_EXT_DEV_PREFIX)

        ip_cidrs = common_utils.fixed_ip_cidrs(ex_gw_port['fixed_ips'])
        self.driver.init_l3(interface_name, ip_cidrs, namespace=ns_name,
                            clean_connections=True)

        self.agent_gateway_port = ex_gw_port

        # enable proxy arp
        cmd = ['sysctl', '-w', 'net.ipv4.conf.%s.proxy_arp=1' % interface_name]
        ip_wrapper.netns.execute(cmd, check_exit_code=False)

    def process_floating_ip_addresses(self, interface_name):
        """Configure IP addresses on router's external gateway interface.

        Ensures addresses for existing floating IPs and cleans up
        those that should not longer be configured.
        """

        fip_statuses = {}
        if interface_name is None:
            LOG.debug('No Interface for floating IPs router: %s',
                      self.router['id'])
            return fip_statuses

        device = ip_lib.IPDevice(interface_name, namespace=self.ns_name)
        existing_cidrs = self.get_router_cidrs(device)
        new_cidrs = set()
        gw_cidrs = self._get_gw_ips_cidr()

        floating_ips = self.get_floating_ips()
        # Loop once to ensure that floating ips are configured.
        for fip in floating_ips:
            fip_ip = fip['floating_ip_address']
            ip_cidr = common_utils.ip_to_cidr(fip_ip)
            new_cidrs.add(ip_cidr)
            fip_statuses[fip['id']] = lib_constants.FLOATINGIP_STATUS_ACTIVE
            cent_router_cidrs = self.get_centralized_router_cidrs()

            if ip_cidr not in existing_cidrs:
                # add_floating_ip is implemented by dvr local object
                fip_statuses[fip['id']] = self.add_floating_ip(
                    fip, interface_name, device)
                LOG.debug('Floating ip %(id)s added, status %(status)s',
                          {'id': fip['id'],
                           'status': fip_statuses.get(fip['id'])})
            elif (fip_ip in self.fip_map and
                  self.fip_map[fip_ip] != fip['fixed_ip_address']):
                LOG.debug("Floating IP was moved from fixed IP "
                          "%(old)s to %(new)s",
                          {'old': self.fip_map[fip_ip],
                           'new': fip['fixed_ip_address']})
                fip_statuses[fip['id']] = self.move_floating_ip(fip)
            elif (ip_cidr in cent_router_cidrs and
                fip.get('host') == self.host):
                LOG.debug("Floating IP is migrating from centralized "
                          "to distributed: %s", fip)
                fip_statuses[fip['id']] = self.migrate_centralized_floating_ip(
                    fip, interface_name, device)
            elif fip_statuses[fip['id']] == fip['status']:
                # mark the status as not changed. we can't remove it because
                # that's how the caller determines that it was removed
                fip_statuses[fip['id']] = FLOATINGIP_STATUS_NOCHANGE
        fips_to_remove = (
            ip_cidr for ip_cidr in existing_cidrs - new_cidrs - gw_cidrs
            if common_utils.is_cidr_host(ip_cidr))
        for ip_cidr in fips_to_remove:
            LOG.debug("Removing floating ip %s from interface %s in "
                      "namespace %s", ip_cidr, interface_name, self.ns_name)
            self.remove_floating_ip(device, ip_cidr)

        return fip_statuses

    def _internal_network_added(self, ns_name, network_id, port_id,
                                fixed_ips, mac_address,
                                interface_name, prefix, mtu=None):
        LOG.debug("adding internal network: prefix(%s), port(%s)",
                  prefix, port_id)
        self.driver.plug(network_id, port_id, interface_name, mac_address,
                         namespace=ns_name,
                         prefix=prefix, mtu=mtu)

        ip_cidrs = common_utils.fixed_ip_cidrs(fixed_ips)
        self.driver.init_router_port(
            interface_name, ip_cidrs, namespace=ns_name)
        for fixed_ip in fixed_ips:
            ip_lib.send_ip_addr_adv_notif(ns_name,
                                          interface_name,
                                          fixed_ip['ip_address'])
```

```python
# implements
class FipNamespace(namespaces.Namespace):

    # create fg-xxx tap device inside of fip namespace
    def create_or_update_gateway_port(self, agent_gateway_port):
        interface_name = self.get_ext_device_name(agent_gateway_port['id'])

        # The lock is used to make sure another thread doesn't call to
        # update the gateway port before we are done initializing things.
        with self._fip_port_lock(interface_name):
            is_first = self.subscribe(agent_gateway_port['network_id'])
            if is_first:
                # Check for subnets that are populated for the agent
                # gateway port that was created on the server.
                if 'subnets' not in agent_gateway_port:
                    return
                self._create_gateway_port(agent_gateway_port, interface_name)
            else:
                try:
                    self._update_gateway_port(
                        agent_gateway_port, interface_name)
                except Exception:
                    pass

    def _update_gateway_port(self, agent_gateway_port, interface_name):
        if (self.agent_gateway_port and
            not self._check_for_gateway_ip_change(agent_gateway_port)):
                return
        # Caller already holding lock
        self._update_gateway_route(
            agent_gateway_port, interface_name, tbl_index=None)

        # Cache the agent gateway port after successfully updating
        # the gateway route, so that checking on self.agent_gateway_port
        # will be a valid check
        self.agent_gateway_port = agent_gateway_port

    def _update_gateway_route(self, agent_gateway_port,
                             interface_name, tbl_index):
        ns_name = self.get_name()
        ipd = ip_lib.IPDevice(interface_name, namespace=ns_name)
        # If the 'fg-' device doesn't exist in the namespace then trying
        # to send advertisements or configure the default route will just
        # throw exceptions.  Unsubscribe this external network so that
        # the next call will trigger the interface to be plugged.
        if not ipd.exists():
            LOG.warning('DVR: FIP gateway port with interface '
                        'name: %(device)s does not exist in the given '
                        'namespace: %(ns)s', {'device': interface_name,
                                              'ns': ns_name})
            msg = _('DVR: Gateway update route in FIP namespace failed, retry '
                    'should be attempted on next call')
            raise n_exc.FloatingIpSetupException(msg)

        for fixed_ip in agent_gateway_port['fixed_ips']:
            ip_lib.send_ip_addr_adv_notif(ns_name,
                                          interface_name,
                                          fixed_ip['ip_address'])

        for subnet in agent_gateway_port['subnets']:
            gw_ip = subnet.get('gateway_ip')
            if gw_ip:
                is_gateway_not_in_subnet = not ipam_utils.check_subnet_ip(
                                                subnet.get('cidr'), gw_ip)
                if is_gateway_not_in_subnet:
                    ipd.route.add_route(gw_ip, scope='link')
                self._add_default_gateway_for_fip(gw_ip, ipd, tbl_index)
            else:
                current_gateway = ipd.route.get_gateway()
                if current_gateway and current_gateway.get('gateway'):
                    ipd.route.delete_gateway(current_gateway.get('gateway'))

    def create_rtr_2_fip_link(self, ri):
        """Create interface between router and Floating IP namespace."""
        LOG.debug("Create FIP link interfaces for router %s", ri.router_id)
        rtr_2_fip_name = self.get_rtr_ext_device_name(ri.router_id)
        fip_2_rtr_name = self.get_int_device_name(ri.router_id)
        fip_ns_name = self.get_name()

        # add link local IP to interface
        if ri.rtr_fip_subnet is None:
            ri.rtr_fip_subnet = self.local_subnets.allocate(ri.router_id)
        rtr_2_fip, fip_2_rtr = ri.rtr_fip_subnet.get_pair()
        rtr_2_fip_dev = ip_lib.IPDevice(rtr_2_fip_name, namespace=ri.ns_name)
        fip_2_rtr_dev = ip_lib.IPDevice(fip_2_rtr_name, namespace=fip_ns_name)

        if not rtr_2_fip_dev.exists():
            ip_wrapper = ip_lib.IPWrapper(namespace=ri.ns_name)
            rtr_2_fip_dev, fip_2_rtr_dev = ip_wrapper.add_veth(rtr_2_fip_name,
                                                               fip_2_rtr_name,
                                                               fip_ns_name)
            mtu = ri.get_ex_gw_port().get('mtu')
            if mtu:
                rtr_2_fip_dev.link.set_mtu(mtu)
                fip_2_rtr_dev.link.set_mtu(mtu)
            rtr_2_fip_dev.link.set_up()
            fip_2_rtr_dev.link.set_up()

        self._add_cidr_to_device(rtr_2_fip_dev, str(rtr_2_fip))
        self._add_cidr_to_device(fip_2_rtr_dev, str(fip_2_rtr))
        self._add_rtr_ext_route_rule_to_route_table(ri, fip_2_rtr,
                                                    fip_2_rtr_name)
```

#### NETWORK FLOW REVIEW

##### FIXED IP

```raw
vm -> qr-xxx (on compute node) -> sg-xxx (snat) -> outside
outside ->  sg-xxx (snat) -> qr-xxx (network node) -> vm
```

##### FLOATING IP

```raw
vm -> qr-xxx (snat/dnat) -> rfp-xxx -> fpr-xxx -> fg-xxx -> outside
outside -> fg-xxx -> fpr-xxx -> rfp-xxx (snat/dnat) -> qr-xxx -> vm
```

### RANDOM RANTS

* My question is why `fip` namespace is necessary? Isn't still possible to make floating ip associate with each router, like what is done in legacy rotuer implementations?

### FIP REFERENCES

* [most refered to article on DVR, very informative](https://assafmuller.com/2015/04/15/distributed-virtual-routing-floating-ips/)