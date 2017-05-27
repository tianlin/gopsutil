// +build windows

package process

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/StackExchange/wmi"
	"github.com/tianlin/w32"

	cpu "github.com/tianlin/gopsutil/cpu"
	"github.com/tianlin/gopsutil/internal/common"
	net "github.com/tianlin/gopsutil/net"
)

const (
	NoMoreFiles        = 0x12
	MaxPathLength      = 260
	PROCESS_ALL_ACCESS = 0x001f0fff
)

var (
	modpsapi    = syscall.NewLazyDLL("psapi.dll")
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")

	procEnumProcesses            = modpsapi.NewProc("EnumProcesses")
	procGetProcessMemoryInfo     = modpsapi.NewProc("GetProcessMemoryInfo")
	procGetProcessTimes          = modkernel32.NewProc("GetProcessTimes")
	procGetProcessImageFileName  = modpsapi.NewProc("GetProcessImageFileNameA")
	procCreateToolhelp32Snapshot = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First           = modkernel32.NewProc("Process32FirstW")

	procGetDiskFreeSpaceExW     = modkernel32.NewProc("GetDiskFreeSpaceExW")
	procGetLogicalDriveStringsW = modkernel32.NewProc("GetLogicalDriveStringsW")
	procGetDriveType            = modkernel32.NewProc("GetDriveTypeW")
	provGetVolumeInformation    = modkernel32.NewProc("GetVolumeInformationW")
)

type PROCESS_MEMORY_COUNTERS_EX struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
	PrivateUsage               uintptr
}

type SystemProcessInformation struct {
	NextEntryOffset   uint64
	NumberOfThreads   uint64
	Reserved1         [48]byte
	Reserved2         [3]byte
	UniqueProcessID   uintptr
	Reserved3         uintptr
	HandleCount       uint64
	Reserved4         [4]byte
	Reserved5         [11]byte
	PeakPagefileUsage uint64
	PrivatePageCount  uint64
	Reserved6         [6]uint64
}

// Memory_info_ex is different between OSes
type MemoryInfoExStat struct {
}

type MemoryMapsStat struct {
}

type Win32_Process struct {
	Name                string
	ExecutablePath      *string
	CommandLine         *string
	Priority            uint32
	CreationDate        *time.Time
	ProcessID           uint32
	ThreadCount         uint32
	Status              *string
	ReadOperationCount  uint64
	ReadTransferCount   uint64
	WriteOperationCount uint64
	WriteTransferCount  uint64

	/*
		CSCreationClassName   string
		CSName                string
		Caption               *string
		CreationClassName     string
		Description           *string
		ExecutionState        *uint16
		HandleCount           uint32
		KernelModeTime        uint64
		MaximumWorkingSetSize *uint32
		MinimumWorkingSetSize *uint32
		OSCreationClassName   string
		OSName                string
		OtherOperationCount   uint64
		OtherTransferCount    uint64
		PageFaults            uint32
		PageFileUsage         uint32
		ParentProcessID       uint32
		PeakPageFileUsage     uint32
		PeakVirtualSize       uint64
		PeakWorkingSetSize    uint32
		PrivatePageCount      uint64
		TerminationDate       *time.Time
		UserModeTime          uint64
		WorkingSetSize        uint64
	*/
}

func Pids() ([]int32, error) {
	var ret []int32

	procs, err := processes()
	if err != nil {
		return ret, nil
	}

	for _, proc := range procs {
		ret = append(ret, proc.Pid)
	}

	return ret, nil
}

func (p *Process) Ppid() (int32, error) {
	ret, _, _, err := p.getFromSnapProcess(p.Pid)
	if err != nil {
		return 0, err
	}
	return ret, nil
}

func GetWin32Proc(pid int32) ([]Win32_Process, error) {
	var dst []Win32_Process
	query := fmt.Sprintf("WHERE ProcessId = %d", pid)
	q := wmi.CreateQuery(&dst, query)
	err := wmi.Query(q, &dst)
	if err != nil {
		return []Win32_Process{}, fmt.Errorf("could not get win32Proc: %s", err)
	}
	if len(dst) != 1 {
		return []Win32_Process{}, fmt.Errorf("could not get win32Proc: empty")
	}
	return dst, nil
}

func (p *Process) Name() (string, error) {
	dst, err := GetWin32Proc(p.Pid)
	if err != nil {
		return "", fmt.Errorf("could not get Name: %s", err)
	}
	return dst[0].Name, nil
}
func (p *Process) Exe() (string, error) {
	dst, err := GetWin32Proc(p.Pid)
	if err != nil {
		return "", fmt.Errorf("could not get ExecutablePath: %s", err)
	}
	return *dst[0].ExecutablePath, nil
}
func (p *Process) Cmdline() (string, error) {
	dst, err := GetWin32Proc(p.Pid)
	if err != nil {
		return "", fmt.Errorf("could not get CommandLine: %s", err)
	}
	return *dst[0].CommandLine, nil
}

// CmdlineSlice returns the command line arguments of the process as a slice with each
// element being an argument. This merely returns the CommandLine informations passed
// to the process split on the 0x20 ASCII character.
func (p *Process) CmdlineSlice() ([]string, error) {
	cmdline, err := p.Cmdline()
	if err != nil {
		return nil, err
	}
	return strings.Split(cmdline, " "), nil
}

func (p *Process) CreateTime() (int64, error) {
	ru, err := getRusage(p.Pid)
	if err != nil {
		return 0, fmt.Errorf("could not get CreationDate: %s", err)
	}

	return ru.CreationTime.Nanoseconds() / 1000000, nil
}

func (p *Process) Cwd() (string, error) {
	return "", common.ErrNotImplementedError
}

func (p *Process) Parent() (*Process, error) {
	return p, common.ErrNotImplementedError
}

func (p *Process) Status() (string, error) {
	handle, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, uint32(p.Pid))

	defer syscall.CloseHandle(handle)

	if err != nil {
		return "unknown", fmt.Errorf("OpenProcess fails with %v", err)
	}

	var ec uint32
	e := syscall.GetExitCodeProcess(syscall.Handle(handle), &ec)
	if e != nil {
		return "unknown", fmt.Errorf("GetExitCodeProcess: %s", e)
	}

	if ec == 259 { //still active
		return "running", nil
	}
	return "sleeping", nil
}

func (p *Process) Username() (string, error) {
	var err error

	handle, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, uint32(p.Pid))

	if err != nil {
		return "", fmt.Errorf("OpenProcess fails with %v", err)
	}

	defer syscall.CloseHandle(handle)

	var token syscall.Token

	// Find process token via win32
	err = syscall.OpenProcessToken(handle, syscall.TOKEN_QUERY, &token)

	if err != nil {
		return "", fmt.Errorf("Error opening process token %v", err)
	}

	// Find the token user
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("Error getting token user %v", err)
	}

	// Close token to prevent handle leaks
	err = token.Close()
	if err != nil {
		return "", fmt.Errorf("Error failed to closed process token")
	}

	// look up domain account by sid
	account, domain, _, err := tokenUser.User.Sid.LookupAccount("localhost")
	if err != nil {
		return "", fmt.Errorf("Error looking up sid %v", err)
	}

	return fmt.Sprintf("%s\\%s", domain, account), nil
}

func (p *Process) Uids() ([]int32, error) {
	var uids []int32

	return uids, common.ErrNotImplementedError
}
func (p *Process) Gids() ([]int32, error) {
	var gids []int32
	return gids, common.ErrNotImplementedError
}
func (p *Process) Terminal() (string, error) {
	return "", common.ErrNotImplementedError
}

// Nice returnes priority in Windows
func (p *Process) Nice() (int32, error) {
	dst, err := GetWin32Proc(p.Pid)
	if err != nil {
		return 0, fmt.Errorf("could not get Priority: %s", err)
	}
	return int32(dst[0].Priority), nil
}
func (p *Process) IOnice() (int32, error) {
	return 0, common.ErrNotImplementedError
}
func (p *Process) Rlimit() ([]RlimitStat, error) {
	var rlimit []RlimitStat

	return rlimit, common.ErrNotImplementedError
}

func (p *Process) IOCounters() (*IOCountersStat, error) {
	dst, err := GetWin32Proc(p.Pid)
	if err != nil || len(dst) == 0 {
		return nil, fmt.Errorf("could not get Win32Proc: %s", err)
	}
	ret := &IOCountersStat{
		ReadCount:  uint64(dst[0].ReadOperationCount),
		ReadBytes:  uint64(dst[0].ReadTransferCount),
		WriteCount: uint64(dst[0].WriteOperationCount),
		WriteBytes: uint64(dst[0].WriteTransferCount),
	}

	return ret, nil
}
func (p *Process) NumCtxSwitches() (*NumCtxSwitchesStat, error) {
	return nil, common.ErrNotImplementedError
}
func (p *Process) NumFDs() (int32, error) {
	return 0, common.ErrNotImplementedError
}
func (p *Process) NumThreads() (int32, error) {
	dst, err := GetWin32Proc(p.Pid)
	if err != nil {
		return 0, fmt.Errorf("could not get ThreadCount: %s", err)
	}
	return int32(dst[0].ThreadCount), nil
}
func (p *Process) Threads() (map[string]string, error) {
	ret := make(map[string]string, 0)
	return ret, common.ErrNotImplementedError
}

func FiletimeToDuration(ft *syscall.Filetime) time.Duration {
	n := int64(ft.HighDateTime)<<32 + int64(ft.LowDateTime) // in 100-nanosecond intervals
	return time.Duration(n*100) * time.Nanosecond
}

func (p *Process) Times() (*cpu.TimesStat, error) {
	handle, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, uint32(p.Pid))

	defer syscall.CloseHandle(handle)

	if err != nil {
		return nil, fmt.Errorf("OpenProcess fails with %v", err)

	}

	var CPU syscall.Rusage
	if err := syscall.GetProcessTimes(handle, &CPU.CreationTime, &CPU.ExitTime, &CPU.KernelTime, &CPU.UserTime); err != nil {
		return nil, fmt.Errorf("GetProcessTimes fails with %v", err)
	}

	stat := cpu.TimesStat{
		User:   float64(FiletimeToDuration(&CPU.UserTime).Seconds()),
		System: float64(FiletimeToDuration(&CPU.KernelTime).Seconds()),
	}

	return &stat, nil
}

func (p *Process) CPUAffinity() ([]int32, error) {
	return nil, common.ErrNotImplementedError
}
func (p *Process) MemoryInfo() (*MemoryInfoStat, error) {
	handle, err := syscall.OpenProcess(PROCESS_ALL_ACCESS, false, uint32(p.Pid))

	defer syscall.CloseHandle(handle)

	if err != nil {
		return nil, fmt.Errorf("OpenProcess fails with %v", err)
	}

	var mem PROCESS_MEMORY_COUNTERS_EX
	mem.CB = uint32(unsafe.Sizeof(mem))

	r1, _, e1 := procGetProcessMemoryInfo.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&mem)),
		uintptr(mem.CB),
	)
	if r1 == 0 {
		if e1 != nil {
			return nil, error(e1)
		} else {
			return nil, syscall.EINVAL
		}
	}

	stat := MemoryInfoStat{
		RSS: uint64(mem.WorkingSetSize),
		VMS: uint64(mem.PrivateUsage),
	}

	// Size contains only to the Private Bytes
	// Virtual Bytes are the Working Set plus paged Private Bytes and standby list.
	return &stat, nil
}

func (p *Process) MemoryInfoEx() (*MemoryInfoExStat, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) Children() ([]*Process, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) OpenFiles() ([]OpenFilesStat, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) Connections() ([]net.ConnectionStat, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) NetIOCounters(pernic bool) ([]net.IOCountersStat, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) IsRunning() (bool, error) {
	return true, common.ErrNotImplementedError
}

func (p *Process) MemoryMaps(grouped bool) (*[]MemoryMapsStat, error) {
	var ret []MemoryMapsStat
	return &ret, common.ErrNotImplementedError
}

func NewProcess(pid int32) (*Process, error) {
	p := &Process{Pid: pid}

	return p, nil
}

func (p *Process) SendSignal(sig syscall.Signal) error {
	return common.ErrNotImplementedError
}

func (p *Process) Suspend() error {
	return common.ErrNotImplementedError
}
func (p *Process) Resume() error {
	return common.ErrNotImplementedError
}

func (p *Process) Terminate() error {
	// PROCESS_TERMINATE = 0x0001
	proc := w32.OpenProcess(0x0001, false, uint32(p.Pid))
	ret := w32.TerminateProcess(proc, 0)
	w32.CloseHandle(proc)

	if ret == false {
		return syscall.GetLastError()
	} else {
		return nil
	}
}

func (p *Process) Kill() error {
	return common.ErrNotImplementedError
}

func (p *Process) getFromSnapProcess(pid int32) (int32, int32, string, error) {
	snap := w32.CreateToolhelp32Snapshot(w32.TH32CS_SNAPPROCESS, uint32(pid))
	if snap == 0 {
		return 0, 0, "", syscall.GetLastError()
	}
	defer w32.CloseHandle(snap)
	var pe32 w32.PROCESSENTRY32
	pe32.DwSize = uint32(unsafe.Sizeof(pe32))
	if w32.Process32First(snap, &pe32) == false {
		return 0, 0, "", syscall.GetLastError()
	}

	if pe32.Th32ProcessID == uint32(pid) {
		szexe := syscall.UTF16ToString(pe32.SzExeFile[:])
		return int32(pe32.Th32ParentProcessID), int32(pe32.CntThreads), szexe, nil
	}

	for w32.Process32Next(snap, &pe32) {
		if pe32.Th32ProcessID == uint32(pid) {
			szexe := syscall.UTF16ToString(pe32.SzExeFile[:])
			return int32(pe32.Th32ParentProcessID), int32(pe32.CntThreads), szexe, nil
		}
	}
	return 0, 0, "", errors.New("Couldn't find pid:" + string(pid))
}

// Get processes
func processes() ([]*Process, error) {

	var dst []Win32_Process
	q := wmi.CreateQuery(&dst, "")
	err := wmi.Query(q, &dst)
	if err != nil {
		return []*Process{}, err
	}
	if len(dst) == 0 {
		return []*Process{}, fmt.Errorf("could not get Process")
	}
	results := make([]*Process, 0, len(dst))
	for _, proc := range dst {
		p, err := NewProcess(int32(proc.ProcessID))
		if err != nil {
			continue
		}
		results = append(results, p)
	}

	return results, nil
}

func getProcInfo(pid int32) (*SystemProcessInformation, error) {
	initialBufferSize := uint64(0x4000)
	bufferSize := initialBufferSize
	buffer := make([]byte, bufferSize)

	var sysProcInfo SystemProcessInformation
	ret, _, _ := common.ProcNtQuerySystemInformation.Call(
		uintptr(unsafe.Pointer(&sysProcInfo)),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&bufferSize)),
		uintptr(unsafe.Pointer(&bufferSize)))
	if ret != 0 {
		return nil, syscall.GetLastError()
	}

	return &sysProcInfo, nil
}

func getRusage(pid int32) (*syscall.Rusage, error) {
	var CPU syscall.Rusage

	c, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(c)

	if err := syscall.GetProcessTimes(c, &CPU.CreationTime, &CPU.ExitTime, &CPU.KernelTime, &CPU.UserTime); err != nil {
		return nil, err
	}

	return &CPU, nil
}

func getMemoryInfo(pid int32) (PROCESS_MEMORY_COUNTERS, error) {
	var mem PROCESS_MEMORY_COUNTERS
	c, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return mem, err
	}
	defer syscall.CloseHandle(c)
	if err := getProcessMemoryInfo(c, &mem); err != nil {
		return mem, err
	}

	return mem, err
}

func getProcessMemoryInfo(h syscall.Handle, mem *PROCESS_MEMORY_COUNTERS) (err error) {
	r1, _, e1 := syscall.Syscall(procGetProcessMemoryInfo.Addr(), 3, uintptr(h), uintptr(unsafe.Pointer(mem)), uintptr(unsafe.Sizeof(*mem)))
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}
