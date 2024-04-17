package main

type bpfSetting int32

const (
	bpfSettingPORT        bpfSetting = 0
	bpfSettingNO_BACKENDS bpfSetting = 1
	bpfSettingOUT_IF      bpfSetting = 2
)
