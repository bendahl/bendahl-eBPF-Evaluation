package main

type bpfSetting uint32

const (
	bpfSettingACTIONS  bpfSetting = 0
	bpfSettingPROTOCOL bpfSetting = 1
	bpfSettingPORT     bpfSetting = 2
	bpfSettingPERCENT  bpfSetting = 3
	bpfSettingMIN_LAT  bpfSetting = 4
	bpfSettingMAX_LAT  bpfSetting = 5
)
