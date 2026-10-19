"""Default passive and explicitly opt-in external adapter registry."""

from .tools import NmapAdapter, NiktoAdapter, NucleiAdapter, OpenSSLAdapter, SslyzeAdapter, TestSSLAdapter, Wafw00fAdapter, WhatWebAdapter, ZapAdapter

adapters = {adapter.name: adapter for adapter in (OpenSSLAdapter, TestSSLAdapter, WhatWebAdapter, Wafw00fAdapter, NmapAdapter, NiktoAdapter, SslyzeAdapter, ZapAdapter)}
adapters["nuclei"] = NucleiAdapter
