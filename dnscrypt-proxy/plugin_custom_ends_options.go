package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

type PluginForwardECIDEntry struct {
	Code uint16
	Data []byte
}

type PluginCustomEdnsOption struct {
	endsOptionList []PluginForwardECIDEntry
}

func (plugin *PluginCustomEdnsOption) Name() string {
	return "custom_edns_option"
}

func (plugin *PluginCustomEdnsOption) Description() string {
	return "Attached custom edns option to query"
}

func (plugin *PluginCustomEdnsOption) Init(proxy *Proxy) error {
	dlog.Noticef("Reading edns option ids list from [%s]", proxy.customEdnsOptionsFile)
	bin, err := ReadTextFile(proxy.customEdnsOptionsFile)
	if err != nil {
		return err
	}

	for lineNo, line := range strings.Split(string(bin), "\n") {
		line = TrimAndStripInlineComments(line)
		if len(line) == 0 {
			continue
		}
		ednsCode, data, ok := StringTwoFields(line)
		if !ok {
			return fmt.Errorf(
				"Syntax error for a cutom edns options at line %d. Expected syntax: FDE9 something",
				1+lineNo,
			)
		}
		code, err := strconv.ParseUint(ednsCode, 16, 16)
		if err != nil {
			return fmt.Errorf(
				"Failed to pars hex number for edns option code at line %d",
				1+lineNo,
			)
		}

		if code < dns.EDNS0LOCALSTART || code > dns.EDNS0LOCALEND {
			return fmt.Errorf("Edns custm code out of range at line %d. Code should be between %d nad %d",
				1+lineNo,
				dns.EDNS0LOCALSTART,
				dns.EDNS0LOCALEND,
			)
		}

		plugin.endsOptionList = append(plugin.endsOptionList, PluginForwardECIDEntry{
			Code: uint16(code),
			Data: []byte(data),
		})
	}

	return nil
}

func (plugin *PluginCustomEdnsOption) Drop() error {
	return nil
}

func (plugin *PluginCustomEdnsOption) Reload() error {
	return nil
}

func (plugin *PluginCustomEdnsOption) Eval(pluginsState *PluginsState, msg *dns.Msg) error {

	edns0 := msg.IsEdns0()
	if edns0 == nil {
		msg.SetEdns0(uint16(MaxDNSPacketSize), false)
		edns0 = msg.IsEdns0()
		if edns0 == nil {
			return nil
		}
	}

	for _, customOption := range plugin.endsOptionList {
		ext := new(dns.EDNS0_LOCAL)
		ext.Code = customOption.Code
		ext.Data = customOption.Data

		edns0.Option = append(edns0.Option, ext)
	}

	return nil
}
