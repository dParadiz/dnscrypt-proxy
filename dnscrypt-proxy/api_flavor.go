package main

import (
	"net"

	clocksmith "github.com/jedisct1/go-clocksmith"
	"github.com/miekg/dns"
)

func (proxy *Proxy) StopProxy() {
	close(proxy.quitListeners)
	proxy.wgQuit.Wait()
}

func (proxy *Proxy) CloseIdleConnections() {
	if proxy.xTransport.transport != nil {
		(*proxy.xTransport.transport).CloseIdleConnections()
	}
}

func (proxy *Proxy) GetPluginsGlobals() *PluginsGlobals {
	return &proxy.pluginsGlobals
}

func (proxy *Proxy) GetIOSMode() bool {
	return proxy.iosMode
}

func (proxy *Proxy) GetPluginBlockIPv6() bool {
	return proxy.pluginBlockIPv6
}

func (proxy *Proxy) GetCloakFile() string {
	return proxy.cloakFile
}

func (proxy *Proxy) GetForwardFile() string {
	return proxy.forwardFile
}

func (proxy *Proxy) GetNXLogFile() string {
	return proxy.nxLogFile
}

func (proxy *Proxy) GetBlockIPFile() string {
	return proxy.blockIPFile
}

func (proxy *Proxy) GetBlockIPLogFile() string {
	return proxy.blockIPLogFile
}

func (proxy *Proxy) GetBlockIPFormat() string {
	return proxy.blockIPFormat
}

func (proxy *Proxy) GetQueryLogFile() string {
	return proxy.queryLogFile
}

func (proxy *Proxy) GetCache() bool {
	return proxy.cache
}

func (proxy *Proxy) GetQueryMeta() []string {
	return proxy.queryMeta
}

func (proxy *Proxy) GetPluginBlockUnqualified() bool {
	return proxy.pluginBlockUnqualified
}

func (proxy *Proxy) GetPluginBlockUndelegated() bool {
	return proxy.pluginBlockUndelegated
}

func (proxy *Proxy) GetBlockNameFile() string {
	return proxy.blockNameFile
}

func (proxy *Proxy) GetWhitelistNameFile() string {
	return proxy.whitelistNameFile
}

func (proxy *Proxy) GetWhitelistNameFormat() string {
	return proxy.whitelistNameFormat
}

func (proxy *Proxy) GetBlockNameFormat() string {
	return proxy.blockNameFormat
}

func (proxy *Proxy) GetBlockNameLogFile() string {
	return proxy.blockNameLogFile
}

func (proxy *Proxy) GetWhitelistNameLogFile() string {
	return proxy.whitelistNameLogFile
}

func (proxy *Proxy) GetDns64Resolvers() []string {
	return proxy.dns64Resolvers
}

func (proxy *Proxy) GetDns64Prefixes() []string {
	return proxy.dns64Prefixes
}

func (proxy *Proxy) GetLogMaxSize() int {
	return proxy.logMaxSize
}

func (proxy *Proxy) GetLogMaxAge() int {
	return proxy.logMaxAge
}

func (proxy *Proxy) GetLogMaxBackups() int {
	return proxy.logMaxBackups
}

func (proxy *Proxy) GetCustomEdnsOptionsFile() string {
	return proxy.customEdnsOptionsFile
}

func (proxy *Proxy) GetAllWeeklyRanges() *map[string]WeeklyRanges {
	return proxy.allWeeklyRanges
}

func (pluginsGlobals *PluginsGlobals) SetQueryPlugins(plugins *[]Plugin) {
	(*pluginsGlobals).queryPlugins = plugins
}

func (pluginsGlobals *PluginsGlobals) SetResponsePlugins(plugins *[]Plugin) {
	(*pluginsGlobals).responsePlugins = plugins
}

func (pluginsGlobals *PluginsGlobals) SetLoggingPlugins(plugins *[]Plugin) {
	(*pluginsGlobals).loggingPlugins = plugins
}

func (pluginsState *PluginsState) GetSessionDataKey(key string) interface{} {
	return pluginsState.sessionData[key]
}

func (pluginsState *PluginsState) SetSessionDataKey(key string, val interface{}) {
	pluginsState.sessionData[key] = val
}

func (pluginsState *PluginsState) GetClientProto() string {
	return pluginsState.clientProto
}

func (pluginsState *PluginsState) GetClientAddr() *net.Addr {
	return pluginsState.clientAddr
}

func (pluginsState *PluginsState) SetAction(action PluginsAction) {
	pluginsState.action = action
}

func (pluginsState *PluginsState) SetReturnCode(code PluginsReturnCode) {
	pluginsState.returnCode = code
}

func (pluginsState *PluginsState) GetQName() string {
	return pluginsState.qName
}

func (proxy *Proxy) RefusedResponseFromQuery(packet []byte) (*dns.Msg, error) {
	msg := dns.Msg{}
	if err := msg.Unpack(packet); err != nil {
		return nil, err
	}

	return RefusedResponseFromMessage(&msg, proxy.pluginsGlobals.refusedCodeInResponses, proxy.pluginsGlobals.respondWithIPv4, proxy.pluginsGlobals.respondWithIPv6, proxy.cacheMinTTL), nil
}

func (xTransport *XTransport) SetupXTransportCloak(useIPv4 bool, useIPv6 bool, fallbackResolver string, ignoreSystemDNS bool) {
	xTransport.useIPv4 = useIPv4
	xTransport.useIPv6 = useIPv6
	xTransport.fallbackResolvers = []string{fallbackResolver}
	xTransport.ignoreSystemDNS = ignoreSystemDNS
	xTransport.rebuildTransport()
}

func PrefetchSourceURLCloak(xTransport *XTransport, url string, cacheFile string, minisignKeyStr string) error {
	_, err := NewSource(url, xTransport, []string{url}, minisignKeyStr, cacheFile, "v2", DefaultPrefetchDelay)
	return err
}

func (proxy *Proxy) RefreshServersInfo() int {
	liveServers, _ := proxy.serversInfo.refresh(proxy)
	if liveServers > 0 {
		return liveServers
	}

	for liveServers == 0 {
		delay := proxy.certRefreshDelayAfterFailure
		clocksmith.Sleep(delay)
		liveServers, _ = proxy.serversInfo.refresh(proxy)
	}

	return liveServers
}

func RefreshServersInfoCloak(proxy *Proxy) {
	proxy.RefreshServersInfo()
}

func DefaultConfig() Config {
	return newConfig()
}
