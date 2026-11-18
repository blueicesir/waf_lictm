package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// File layout constants (reverse-engineered from lictm ELF binary)
const (
	DEFAULT_LIC_PATH = "/RayOS/cfg/license/.lic.running"
	LOCAL_LIC_PATH   = ".lic.running"
	LSB_VERSION      = "20221026.docker"

	HEADER_SIZE = 0x1AC // 428 bytes
	RECORD_SIZE = 388   // bytes per record
	MAX_RECORDS = 128   // total record slots
	KEY_SIZE    = 128
	TYPE_SIZE   = 4
	VALUE_SIZE  = 124
	DESC_SIZE   = 128
	PAD_SIZE    = 4
	SPECIAL_REC = 127 // last record: UUID and system metadata

	// Header field offsets
	HDR_IS_LIC_EXIST = 0x00
	HDR_MAX_RECORDS  = 0x04
	HDR_RECORD_FLAG  = 0x08
	HDR_LIC_VERSION  = 0x0C
	HDR_LICENSE_KEY  = 0x10
	HDR_CREATE_TS    = 0x14
	HDR_RESERVED     = 0x18
	HDR_WRITE_TS     = 0x1C
	HDR_EXPIRE_STR   = 0x20 // 32 bytes: "YYYY-MM-DD HH:MM:SS\0"

	// Record value types
	TYPE_INT       = 0x00000
	TYPE_STRING    = 0x00001
	TYPE_BOOL      = 0x00002
	TYPE_TIMESTAMP = 0x10000
)

// FileHeader represents the 428-byte header of .lic.running
type FileHeader struct {
	IsLicExist  uint32 // 0x00: 1 = license exists
	MaxRecords  uint32 // 0x04: max record slots (256)
	RecordFlag  uint32 // 0x08: flag (always 1)
	LicVersion  uint32 // 0x0C: license version number
	LicenseKey  uint32 // 0x10: license key/serial
	CreateTS    uint32 // 0x14: license create timestamp
	Reserved    uint32 // 0x18: reserved (0)
	WriteTS     uint32 // 0x1C: last write timestamp
	ExpireDateS string // 0x20: expire date string "YYYY-MM-DD HH:MM:SS"
}

// Record represents one 388-byte license record
type Record struct {
	Key   string // 128 bytes, C-string null-padded
	Type  uint32 // 4 bytes: 0=int, 1=string, 2=YES/NO bool, 0x10000=timestamp
	Value string // 124 bytes, C-string
	Desc  string // 128 bytes, description
}

// SpecialRecord (record 127) stores UUID and system metadata
type SpecialRecord struct {
	TypeChar    byte
	UUID1       string
	UUID2       string
	LicVersion  uint32
	MaxRecords  uint32
	Field1      uint32
	Field2      uint32
	InstallDate string // "YYYYMMDDHHmmss"
}

// LicRunning is the parsed .lic.running file
type LicRunning struct {
	Header  FileHeader
	Records []Record
	Special SpecialRecord
}

// readCString reads a null-terminated string from a fixed-size byte slice
func readCString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// resolveLicPath checks for default system path or fallback to local directory
func resolveLicPath(explicitPath string) string {
	if explicitPath != "" && explicitPath != DEFAULT_LIC_PATH {
		return explicitPath
	}
	if _, err := os.Stat(DEFAULT_LIC_PATH); err == nil {
		return DEFAULT_LIC_PATH
	}
	if _, err := os.Stat(LOCAL_LIC_PATH); err == nil {
		return LOCAL_LIC_PATH
	}
	return DEFAULT_LIC_PATH
}

// parseLicRunning parses the binary .lic.running file
func parseLicRunning(path string) (*LicRunning, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", path, err)
	}

	expectedMin := HEADER_SIZE + MAX_RECORDS*RECORD_SIZE
	if len(data) < expectedMin {
		return nil, fmt.Errorf("file too small: %d bytes (need >= %d)", len(data), expectedMin)
	}

	lic := &LicRunning{}

	// --- Parse header ---
	hdr := &lic.Header
	hdr.IsLicExist = binary.LittleEndian.Uint32(data[HDR_IS_LIC_EXIST : HDR_IS_LIC_EXIST+4])
	hdr.MaxRecords = binary.LittleEndian.Uint32(data[HDR_MAX_RECORDS : HDR_MAX_RECORDS+4])
	hdr.RecordFlag = binary.LittleEndian.Uint32(data[HDR_RECORD_FLAG : HDR_RECORD_FLAG+4])
	hdr.LicVersion = binary.LittleEndian.Uint32(data[HDR_LIC_VERSION : HDR_LIC_VERSION+4])
	hdr.LicenseKey = binary.LittleEndian.Uint32(data[HDR_LICENSE_KEY : HDR_LICENSE_KEY+4])
	hdr.CreateTS = binary.LittleEndian.Uint32(data[HDR_CREATE_TS : HDR_CREATE_TS+4])
	hdr.Reserved = binary.LittleEndian.Uint32(data[HDR_RESERVED : HDR_RESERVED+4])
	hdr.WriteTS = binary.LittleEndian.Uint32(data[HDR_WRITE_TS : HDR_WRITE_TS+4])
	hdr.ExpireDateS = readCString(data[HDR_EXPIRE_STR : HDR_EXPIRE_STR+32])

	// --- Parse records ---
	lic.Records = make([]Record, MAX_RECORDS)
	for i := 0; i < MAX_RECORDS; i++ {
		off := HEADER_SIZE + i*RECORD_SIZE
		if off+RECORD_SIZE > len(data) {
			break
		}

		rec := &lic.Records[i]
		rec.Key = readCString(data[off : off+KEY_SIZE])
		rec.Type = binary.LittleEndian.Uint32(data[off+KEY_SIZE : off+KEY_SIZE+TYPE_SIZE])
		rec.Value = readCString(data[off+KEY_SIZE+TYPE_SIZE : off+KEY_SIZE+TYPE_SIZE+VALUE_SIZE])
		rec.Desc = readCString(data[off+KEY_SIZE+TYPE_SIZE+VALUE_SIZE : off+KEY_SIZE+TYPE_SIZE+VALUE_SIZE+DESC_SIZE])
	}

	// --- Parse special record (index 127) ---
	spOff := HEADER_SIZE + SPECIAL_REC*RECORD_SIZE
	if spOff+RECORD_SIZE <= len(data) {
		sp := &lic.Special
		sp.TypeChar = data[spOff]
		// UUID1 at +4, 36 bytes (null-terminated)
		if spOff+4+36 <= len(data) {
			sp.UUID1 = readCString(data[spOff+4 : spOff+4+36])
		}
		// UUID2 at +0x44, 36 bytes (null-terminated)
		if spOff+0x44+36 <= len(data) {
			sp.UUID2 = readCString(data[spOff+0x44 : spOff+0x44+36])
		}
		if spOff+0x84+16 <= len(data) {
			sp.LicVersion = binary.LittleEndian.Uint32(data[spOff+0x84 : spOff+0x88])
			sp.MaxRecords = binary.LittleEndian.Uint32(data[spOff+0x88 : spOff+0x8C])
			sp.Field1 = binary.LittleEndian.Uint32(data[spOff+0x8C : spOff+0x90])
			sp.Field2 = binary.LittleEndian.Uint32(data[spOff+0x90 : spOff+0x94])
		}
		if spOff+0x98+14 <= len(data) {
			sp.InstallDate = readCString(data[spOff+0x98 : spOff+0x98+14])
		}
	}

	return lic, nil
}

// findRecord finds a record by key name
func (lic *LicRunning) findRecord(key string) *Record {
	for i := range lic.Records {
		if lic.Records[i].Key == key {
			return &lic.Records[i]
		}
	}
	return nil
}

// getVal returns the value string for a key, or "" if not found
func (lic *LicRunning) getVal(key string) string {
	r := lic.findRecord(key)
	if r == nil {
		return ""
	}
	return r.Value
}

// tsToStr converts a unix timestamp to "YYYY-MM-DD HH:MM:SS"
func tsToStr(ts uint32) string {
	if ts == 0 {
		return "0000-00-00 00:00:00"
	}
	t := time.Unix(int64(ts), 0).Local()
	return t.Format("2006-01-02 15:04:05")
}

// timeLeftStr formats seconds into " %d days %d hours %d minutes %d secs"
func timeLeftStr(secs int64) string {
	if secs <= 0 {
		return " 0 days 0 hours 0 minutes 0 secs"
	}
	days := secs / 86400
	rem := secs % 86400
	hours := rem / 3600
	rem = rem % 3600
	minutes := rem / 60
	s := rem % 60
	return fmt.Sprintf(" %d days %d hours %d minutes %d secs", days, hours, minutes, s)
}

// computeTimeLeft calculates seconds left until expiry
func computeTimeLeft(expireStr string) int64 {
	if expireStr == "" {
		return 0
	}
	t, err := time.ParseInLocation("2006-01-02 15:04:05", expireStr, time.Local)
	if err != nil {
		return 0
	}
	left := time.Until(t).Seconds()
	if left < 0 {
		return 0
	}
	return int64(left)
}

// licType returns the license type string
func licType() string {
	return "NORMAL"
}

// cmdShowL prints runtime license info (exact match to lictm -L)
func cmdShowL(lic *LicRunning, showItems bool) {
	hdr := &lic.Header
	sp := &lic.Special

	expireDateStr := hdr.ExpireDateS
	timeLeftSecs := computeTimeLeft(expireDateStr)
	timeLeftDays := timeLeftSecs / 86400

	isLicExist := "false"
	if hdr.IsLicExist != 0 {
		isLicExist = "true"
	}
	isLicValid := "false"
	if hdr.IsLicExist != 0 && timeLeftSecs > 0 {
		isLicValid = "true"
	}

	isTrial := lic.getVal("is_trial")
	if isTrial == "" {
		isTrial = "NO"
	}

	createTimeStr := tsToStr(hdr.CreateTS)
	writeTimeStr := tsToStr(hdr.WriteTS)

	// Count named records
	tplItemCnt := 0
	for _, r := range lic.Records {
		if r.Key != "" && r.Key != "2" {
			tplItemCnt++
		}
	}

	// Exact format strings reverse-engineered from lictm binary
	fmt.Println("==========================================================================")
	fmt.Println("license:")
	fmt.Printf("\t dev_id:\t[%s]\n", sp.UUID1)
	fmt.Printf("\t hw_id: \t[%s]\n", sp.UUID2)
	fmt.Printf("\t time_limit:\t[%d] (day)\n", timeLeftDays)
	fmt.Printf("\t lic_version:\t[%d] \n", hdr.LicVersion)
	fmt.Printf("\t is_trial:\t[%s]\n", isTrial)
	fmt.Printf("\t lic_type:\t[%s]\n", licType())
	fmt.Printf("\t counter:\t[%d]\n", sp.Field2)
	fmt.Printf("\t tpl_itm_cnt:\t[%d]\n", tplItemCnt)
	fmt.Printf("\t time_stamp:\t[%s]\n", writeTimeStr)
	fmt.Println("##########################################################################")
	fmt.Println("runtime_license:")
	fmt.Printf("\t is_lic_exist:\t[%s]\n", isLicExist)
	fmt.Printf("\t is_lic_valid:\t[%s]\n", isLicValid)
	fmt.Printf("\t lsb_version:\t[%s]\n", LSB_VERSION)
	fmt.Printf("\t time_limit:\t[%d days]\n", timeLeftDays)
	fmt.Printf("\t time_left:\t[%d secs]\n", timeLeftSecs)
	fmt.Printf("\t time_left:\t[%s]\n", timeLeftStr(timeLeftSecs))
	fmt.Printf("\t expire_date:\t[%s]\n", expireDateStr)
	fmt.Printf("\t start_time:\t[%s]\n", createTimeStr)
	fmt.Printf("\t last_shutdown_time:\t[%s]\n", writeTimeStr)
	fmt.Printf("\t last_update_time:\t[%s]\n", writeTimeStr)

	if showItems {
		fmt.Println("##########################################################################")
		fmt.Println("license items:")
		for _, r := range lic.Records {
			if r.Key == "" || r.Key == "2" {
				continue
			}
			switch r.Type {
			case TYPE_BOOL:
				enabled := "disable"
				if strings.ToUpper(r.Value) == "YES" {
					enabled = "enable"
				}
				fmt.Printf("  %-32s %s\n", r.Key, enabled)
			case TYPE_TIMESTAMP:
				fmt.Printf("  %-32s [timestamp]\n", r.Key)
			default:
				fmt.Printf("  %-32s %s\n", r.Key, r.Value)
			}
		}
	}
}

// cmdShowJ prints JSON runtime license data (lictm -J)
func cmdShowJ(lic *LicRunning) {
	hdr := &lic.Header
	sp := &lic.Special

	expireDateStr := hdr.ExpireDateS
	timeLeftSecs := computeTimeLeft(expireDateStr)
	timeLeftDays := timeLeftSecs / 86400

	isLicExist := "false"
	if hdr.IsLicExist != 0 {
		isLicExist = "true"
	}
	isLicValid := "false"
	if hdr.IsLicExist != 0 && timeLeftSecs > 0 {
		isLicValid = "true"
	}

	createTimeStr := tsToStr(hdr.CreateTS)
	writeTimeStr := tsToStr(hdr.WriteTS)

	inner := map[string]interface{}{
		"is_lic_exist":       isLicExist,
		"lic_version":        hdr.LicVersion,
		"is_lic_valid":       isLicValid,
		"time_left_in_sec":   fmt.Sprintf("%d/secs", timeLeftSecs),
		"time_left":          fmt.Sprintf("%d/days", timeLeftDays),
		"expire_date":        expireDateStr,
		"start_time":         createTimeStr,
		"last_shutdown_time": writeTimeStr,
		"last_update_time":   writeTimeStr,
		"dev_id":             sp.UUID1,
		"hw_id":              sp.UUID2,
		"lic_type":           licType(),
		"counter":            sp.Field2,
		"time_stamp":         writeTimeStr,
	}

	out := map[string]interface{}{
		"runtime-lic": inner,
	}

	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] failed to get runtime lic data in json!\n")
		os.Exit(1)
	}
	fmt.Println(string(b))
}

// cmdVersion prints LSB version (lictm -V / --version)
func cmdVersion() {
	fmt.Printf("lsb_version:[%s]\n", LSB_VERSION)
}

// cmdReset simulates cache reset (lictm -R / --reset)
func cmdReset() {
	hwIDFile := "/tmp/.lic.hw.id"
	if err := os.Remove(hwIDFile); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "[WARN] could not remove %s: %v\n", hwIDFile, err)
	}
	fmt.Println("-reset Reset status OK!")
}

// cmdAdd simulates USB add / reload (lictm -A / --add)
func cmdAdd() {
	hwIDFile := "/tmp/.lic.hw.id"
	if err := os.Remove(hwIDFile); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "[WARN] could not remove %s: %v\n", hwIDFile, err)
	}
	fmt.Println("Reset status OK!")
}

// cmdInit checks or initializes runtime license (lictm -I)
func cmdInit(licFile string) {
	_, err := os.Stat(licFile)
	if err == nil {
		fmt.Printf("[INFO] runtime license already exists: %s\n", licFile)
		return
	}
	fmt.Printf("[INFO] runtime license file not found, would init from license_in_use.dat\n")
}

func usage() {
	fmt.Fprintf(os.Stderr, `lictm / golictm - License manager tool (Go equivalent)

Usage:
  golictm -L            /  show runtime license info!
  golictm -S            /  start license ,keep license running,called when os is booted!
  golictm -I            /  init runtime license if needed!
  golictm -R/--reset    /  Remove cache, read hw info from hardware, log remove usb!
  golictm -A/--add      /  Remove cache, read hw info from hardware, log add usb!
  golictm -V/--version  /  show lsb verison!
  golictm -J            /  output runtime lic data in json!

Extended Options:
  -items                show all license items detail in -L output
  -f <path>             custom path to .lic.running (default: %s or ./%s)
`, DEFAULT_LIC_PATH, LOCAL_LIC_PATH)
}

func main() {
	var (
		flagL       = flag.Bool("L", false, "show runtime license info")
		flagS       = flag.Bool("S", false, "start license daemon")
		flagI       = flag.Bool("I", false, "init runtime license")
		flagR       = flag.Bool("R", false, "reset cache (remove usb)")
		flagReset   = flag.Bool("reset", false, "reset cache (remove usb)")
		flagA       = flag.Bool("A", false, "add usb / refresh cache")
		flagAdd     = flag.Bool("add", false, "add usb / refresh cache")
		flagV       = flag.Bool("V", false, "show lsb version")
		flagVersion = flag.Bool("version", false, "show lsb version")
		flagJ       = flag.Bool("J", false, "output runtime lic as JSON")
		flagItems   = flag.Bool("items", false, "display all license item features")
		flagFile    = flag.String("f", "", "path to .lic.running file")
	)

	flag.Usage = usage
	flag.Parse()

	// Handle version first
	if *flagV || *flagVersion {
		cmdVersion()
		return
	}

	// Handle cache reset / add
	if *flagR || *flagReset {
		cmdReset()
		return
	}
	if *flagA || *flagAdd {
		cmdAdd()
		return
	}

	// Daemon mode placeholder
	if *flagS {
		fmt.Println("[INFO] daemon mode not implemented in golictm")
		return
	}

	resolvedPath := resolveLicPath(*flagFile)

	// Init mode
	if *flagI {
		cmdInit(resolvedPath)
		return
	}

	if !*flagL && !*flagJ {
		usage()
		os.Exit(1)
	}

	lic, err := parseLicRunning(resolvedPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] failed to get runtime lic data! (%v)\n", err)
		os.Exit(1)
	}

	switch {
	case *flagL:
		cmdShowL(lic, *flagItems)
	case *flagJ:
		cmdShowJ(lic)
	}
}

