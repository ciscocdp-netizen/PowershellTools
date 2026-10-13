<#
.SYNOPSIS
    SMBv1 Traffic Analyzer - Wireshark-style live capture GUI for Windows PowerShell 5.1.

.DESCRIPTION
    Interactive packet analyzer that finds and decodes SMBv1 (and SMBv2/v3) on the local
    Windows server. Designed for Windows Server 2012 R2 and older hosts running
    Windows PowerShell 5.1. No Npcap, WinPcap, or Wireshark install is required.

    Live capture uses a raw IPv4 socket (SIO_RCVALL) bound to a local interface, which
    requires an elevated Administrator session. Packets are parsed in a background C#
    engine and displayed in a three-pane Wireshark-like layout:

      1. Color-coded packet list (filter, sort, mark, follow stream)
      2. Protocol details tree (IP / TCP / NetBIOS / SMB)
      3. Hex dump with the SMB signature highlighted

    Additional tabs: SMBv1 hosts, live statistics, server SMB configuration / hardening,
    Windows event-log scan, and an in-app manual.

    Display filters (examples):
      smb1
      smb1 and negotiate
      ip.addr==10.1.1.8
      tcp.port==445 and smb1
      user:CONTOSO
      file:data.mdb
      not smb2

.PARAMETER SelfTest
    Compile the parser, inject synthetic SMBv1/SMB2 frames, round-trip a PCAP, and exit
    without showing the GUI. Exit code 0 = pass.

.PARAMETER OpenPcap
    Optional path to a .pcap / .cap file to load at startup.

.PARAMETER InterfaceIP
    Optional IPv4 address of the capture interface to pre-select.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -STA -File .\SMBv1-TrafficAnalyzer.ps1

.EXAMPLE
    .\SMBv1-TrafficAnalyzer.ps1 -SelfTest

.NOTES
    Version     : 1.0
    Compatible  : Windows PowerShell 5.1 on Windows Server 2012 / 2012 R2 / 2008 R2 (WMF 5.1)
    Privileges  : Administrator for live capture and SMB hardening; offline PCAP review does not
                  require elevation.
    Signature   : SMBv1 = 0xFF 'SMB'   SMBv2/v3 = 0xFE 'SMB'   SMB3 transform = 0xFD 'SMB'
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$SelfTest,
    [string]$OpenPcap,
    [string]$InterfaceIP
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:AppVersion = '1.0'

# ============================================================
# STA APARTMENT (required for WinForms)
# ============================================================
if (-not $SelfTest) {
    $apartment = [System.Threading.Thread]::CurrentThread.GetApartmentState()
    if ($apartment -ne 'STA' -and $PSCommandPath) {
        $argList = "-NoProfile -ExecutionPolicy Bypass -STA -File `"$PSCommandPath`""
        if ($OpenPcap)    { $argList += " -OpenPcap `"$OpenPcap`"" }
        if ($InterfaceIP) { $argList += " -InterfaceIP `"$InterfaceIP`"" }
        Start-Process -FilePath "powershell.exe" -ArgumentList $argList
        return
    }
}

# ============================================================
# C# PACKET ENGINE
# C# 5 / .NET 4.5 only (Windows 2012 R2 compiler). No C# 6 syntax.
# ============================================================
$script:EngineTypeName = 'SmbCaptureEngine'
if (-not ($script:EngineTypeName -as [type])) {
    $cs = @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

public class SmbPacket {
    public int No;
    public DateTime Time;
    public string Src = "";
    public string Dst = "";
    public int SrcPort;
    public int DstPort;
    public string Protocol = "TCP";
    public int Length;
    public string Info = "";
    public byte[] Raw;
    public string SmbVersion = "";
    public string SmbCommand = "";
    public int SmbCommandCode = -1;
    public uint NtStatus;
    public ushort Tid;
    public ushort Pid;
    public ushort Uid;
    public ushort Mid;
    public bool IsSmb1;
    public bool IsSmb2;
    public bool IsSmb3;
    public bool HasSmb;
    public bool IsNegotiate;
    public bool IsSessionSetup;
    public bool IsTreeConnect;
    public bool IsNtCreate;
    public byte TcpFlags;
    public uint Seq;
    public uint Ack;
    public int IpHeaderLen;
    public int TcpHeaderLen;
    public int PayloadOffset;
    public int PayloadLength;
    public int SmbOffset = -1;
    public string Dialects = "";
    public string UserName = "";
    public string Workstation = "";
    public string SharePath = "";
    public string FileName = "";
    public bool Marked;
}

public class CaptureStats {
    public int Captured;
    public int Smb1;
    public int Smb2;
    public int Smb3;
    public int Dropped;
    public int Queue;
    public long Bytes;
}

public static class SmbPacketParser {
    public static SmbPacket ParseIpPacket(byte[] raw, DateTime time) {
        if (raw == null || raw.Length < 20) return null;
        int verIhl = raw[0];
        if (((verIhl >> 4) & 0x0F) != 4) return null;
        int ihl = (verIhl & 0x0F) * 4;
        if (ihl < 20 || raw.Length < ihl) return null;

        SmbPacket p = new SmbPacket();
        p.Time = time;
        p.Raw = raw;
        p.Length = raw.Length;
        p.IpHeaderLen = ihl;
        p.Src = raw[12] + "." + raw[13] + "." + raw[14] + "." + raw[15];
        p.Dst = raw[16] + "." + raw[17] + "." + raw[18] + "." + raw[19];

        int proto = raw[9];
        if (proto != 6) {
            p.Protocol = "IP";
            p.Info = "IP protocol " + proto;
            return p;
        }
        if (raw.Length < ihl + 20) {
            p.Protocol = "TCP";
            p.Info = "Truncated TCP header";
            return p;
        }

        int t = ihl;
        p.SrcPort = (raw[t] << 8) | raw[t + 1];
        p.DstPort = (raw[t + 2] << 8) | raw[t + 3];
        p.Seq = (uint)((raw[t + 4] << 24) | (raw[t + 5] << 16) | (raw[t + 6] << 8) | raw[t + 7]);
        p.Ack = (uint)((raw[t + 8] << 24) | (raw[t + 9] << 16) | (raw[t + 10] << 8) | raw[t + 11]);
        int tcpLen = ((raw[t + 12] >> 4) & 0x0F) * 4;
        if (tcpLen < 20) tcpLen = 20;
        p.TcpHeaderLen = tcpLen;
        p.TcpFlags = raw[t + 13];
        p.PayloadOffset = t + tcpLen;
        p.PayloadLength = raw.Length - p.PayloadOffset;
        if (p.PayloadLength < 0) p.PayloadLength = 0;

        ParseSmb(p);
        if (!p.HasSmb) {
            p.Protocol = "TCP";
            p.Info = FormatTcpInfo(p);
        }
        return p;
    }

    static void ParseSmb(SmbPacket p) {
        byte[] raw = p.Raw;
        int off = p.PayloadOffset;
        int len = p.PayloadLength;
        if (len < 4 || off < 0 || off + 4 > raw.Length) return;

        int smbAt = FindSmbMagic(raw, off, len);
        if (smbAt < 0) return;

        p.HasSmb = true;
        p.SmbOffset = smbAt;
        byte mag = raw[smbAt];
        if (mag == 0xFF) {
            p.IsSmb1 = true;
            p.SmbVersion = "SMBv1";
            p.Protocol = "SMB1";
            ParseSmb1(p, smbAt);
        } else if (mag == 0xFE) {
            p.IsSmb2 = true;
            p.SmbVersion = "SMBv2";
            p.Protocol = "SMB2";
            ParseSmb2(p, smbAt);
        } else if (mag == 0xFD) {
            p.IsSmb3 = true;
            p.SmbVersion = "SMB3 Transform";
            p.Protocol = "SMB3";
            p.Info = "SMB3 encryption transform header";
        }
    }

    static int FindSmbMagic(byte[] raw, int off, int len) {
        int last = off + len - 4;
        if (last >= raw.Length) last = raw.Length - 4;
        if (off + 4 <= last && IsSmbMagic(raw, off + 4)) return off + 4;
        if (IsSmbMagic(raw, off)) return off;
        int maxScan = off + Math.Min(len, 256);
        if (maxScan > last + 1) maxScan = last + 1;
        for (int i = off + 1; i < maxScan; i++) {
            if (IsSmbMagic(raw, i)) return i;
        }
        return -1;
    }

    static bool IsSmbMagic(byte[] raw, int i) {
        if (i < 0 || i + 3 >= raw.Length) return false;
        byte m = raw[i];
        return (m == 0xFF || m == 0xFE || m == 0xFD)
            && raw[i + 1] == 0x53 && raw[i + 2] == 0x4D && raw[i + 3] == 0x42;
    }

    static void ParseSmb1(SmbPacket p, int smbAt) {
        byte[] raw = p.Raw;
        if (smbAt + 32 > raw.Length) {
            p.Info = "SMBv1 (truncated header)";
            return;
        }
        int cmd = raw[smbAt + 4];
        p.SmbCommandCode = cmd;
        p.SmbCommand = Smb1CommandName(cmd);
        p.NtStatus = BitConverter.ToUInt32(raw, smbAt + 5);
        byte flags = raw[smbAt + 9];
        ushort flags2 = BitConverter.ToUInt16(raw, smbAt + 10);
        p.Tid = BitConverter.ToUInt16(raw, smbAt + 24);
        p.Pid = BitConverter.ToUInt16(raw, smbAt + 26);
        p.Uid = BitConverter.ToUInt16(raw, smbAt + 28);
        p.Mid = BitConverter.ToUInt16(raw, smbAt + 30);
        bool reply = (flags & 0x80) != 0;
        string dir = reply ? "Response" : "Request";
        p.Info = "SMBv1 " + p.SmbCommand + " " + dir;

        if (cmd == 0x72) p.IsNegotiate = true;
        if (cmd == 0x73) p.IsSessionSetup = true;
        if (cmd == 0x70 || cmd == 0x75) p.IsTreeConnect = true;
        if (cmd == 0xA2 || cmd == 0x03 || cmd == 0x2D) p.IsNtCreate = true;

        if (cmd == 0x72 && !reply) {
            p.Dialects = ParseSmb1Dialects(raw, smbAt + 32, raw.Length);
            if (p.Dialects.Length > 0) p.Info += ", Dialects: " + p.Dialects;
        }
        if (cmd == 0x72 && reply) {
            if (smbAt + 35 <= raw.Length) {
                ushort idx = BitConverter.ToUInt16(raw, smbAt + 33);
                p.Info += ", DialectIndex=" + idx;
            }
        }

        ParseNtlm(p, raw, smbAt, raw.Length);
        if (cmd == 0x75 || cmd == 0x70) {
            string path = FindUncPath(raw, smbAt + 32, raw.Length);
            if (path.Length > 0) {
                p.SharePath = path;
                p.Info += ", Tree: " + path;
            }
        }
        if (cmd == 0xA2 && !reply) {
            string fn = ExtractSmb1TrailingString(raw, smbAt, flags2);
            if (fn.Length > 0) {
                p.FileName = fn;
                p.Info += ", File: " + fn;
            }
        }
        if (p.NtStatus != 0) {
            p.Info += ", Status=" + StatusName(p.NtStatus);
        }
    }

    static void ParseSmb2(SmbPacket p, int smbAt) {
        byte[] raw = p.Raw;
        if (smbAt + 16 > raw.Length) {
            p.Info = "SMB2 (truncated header)";
            return;
        }
        ushort cmd = BitConverter.ToUInt16(raw, smbAt + 12);
        p.SmbCommandCode = cmd;
        p.SmbCommand = Smb2CommandName(cmd);
        uint flags = 0;
        if (smbAt + 20 <= raw.Length) flags = BitConverter.ToUInt32(raw, smbAt + 16);
        bool reply = (flags & 0x00000001) != 0;
        if (smbAt + 12 <= raw.Length) p.NtStatus = BitConverter.ToUInt32(raw, smbAt + 8);
        string dir = reply ? "Response" : "Request";
        p.Info = "SMB2 " + p.SmbCommand + " " + dir;

        if (cmd == 0) p.IsNegotiate = true;
        if (cmd == 1) p.IsSessionSetup = true;
        if (cmd == 3) p.IsTreeConnect = true;
        if (cmd == 5) p.IsNtCreate = true;

        if (cmd == 0 && !reply) {
            p.Dialects = ParseSmb2Dialects(raw, smbAt, raw.Length);
            if (p.Dialects.Length > 0) p.Info += ", Dialects: " + p.Dialects;
        }
        if (cmd == 0 && reply && smbAt + 70 <= raw.Length) {
            ushort dialect = BitConverter.ToUInt16(raw, smbAt + 68);
            p.Info += ", Dialect=" + DialectHex(dialect);
            if (dialect >= 0x0300) {
                p.IsSmb3 = true;
                p.IsSmb2 = false;
                p.Protocol = "SMB3";
                p.SmbVersion = "SMBv3";
                p.Info = p.Info.Replace("SMB2 ", "SMB3 ");
            }
        }
        ParseNtlm(p, raw, smbAt, raw.Length);
        if (p.NtStatus != 0 && reply) p.Info += ", Status=" + StatusName(p.NtStatus);
    }

    static string ParseSmb1Dialects(byte[] raw, int pos, int end) {
        if (pos >= end) return "";
        int wc = raw[pos];
        pos = pos + 1 + (wc * 2);
        if (pos + 2 > end) return "";
        int bcc = BitConverter.ToUInt16(raw, pos);
        pos += 2;
        int stop = pos + bcc;
        if (stop > end) stop = end;
        List<string> list = new List<string>();
        while (pos < stop) {
            if (raw[pos] == 0x02) pos++;
            StringBuilder sb = new StringBuilder();
            while (pos < stop && raw[pos] != 0 && sb.Length < 64) {
                char c = (char)raw[pos];
                if (c >= 32 && c < 127) sb.Append(c);
                pos++;
            }
            pos++;
            if (sb.Length > 0) list.Add(sb.ToString());
            if (list.Count >= 12) break;
        }
        return string.Join(", ", list.ToArray());
    }

    static string ParseSmb2Dialects(byte[] raw, int smbAt, int end) {
        int pos = smbAt + 64;
        if (pos + 8 > end) return "";
        ushort dialectCount = BitConverter.ToUInt16(raw, pos + 2);
        pos += 36;
        if (pos + dialectCount * 2 > end) dialectCount = (ushort)Math.Max(0, (end - pos) / 2);
        List<string> list = new List<string>();
        for (int i = 0; i < dialectCount && i < 16; i++) {
            ushort d = BitConverter.ToUInt16(raw, pos + (i * 2));
            list.Add(DialectHex(d));
        }
        return string.Join(", ", list.ToArray());
    }

    static string ExtractSmb1TrailingString(byte[] raw, int smbAt, ushort flags2) {
        int pos = smbAt + 32;
        if (pos >= raw.Length) return "";
        int wc = raw[pos];
        pos = pos + 1 + (wc * 2);
        if (pos + 2 > raw.Length) return "";
        int bcc = BitConverter.ToUInt16(raw, pos);
        pos += 2;
        int stop = pos + bcc;
        if (stop > raw.Length) stop = raw.Length;
        bool unicode = (flags2 & 0x8000) != 0;
        if (unicode) {
            if ((pos % 2) == 1) pos++;
            StringBuilder sb = new StringBuilder();
            while (pos + 1 < stop && sb.Length < 180) {
                int ch = raw[pos] | (raw[pos + 1] << 8);
                pos += 2;
                if (ch == 0) break;
                if (ch >= 32 && ch < 127) sb.Append((char)ch);
                else if (ch > 127) sb.Append('?');
            }
            return sb.ToString();
        }
        StringBuilder a = new StringBuilder();
        while (pos < stop && raw[pos] != 0 && a.Length < 180) {
            char c = (char)raw[pos++];
            if (c >= 32 && c < 127) a.Append(c);
        }
        return a.ToString();
    }

    static string FindUncPath(byte[] raw, int start, int end) {
        for (int i = start; i + 3 < end && i < start + 800; i++) {
            if (raw[i] == (byte)'\\' && raw[i + 1] == (byte)'\\') {
                StringBuilder sb = new StringBuilder();
                int j = i;
                while (j < end && j < i + 180 && raw[j] >= 32 && raw[j] < 127) {
                    sb.Append((char)raw[j]);
                    j++;
                }
                if (sb.Length >= 4) return sb.ToString();
            }
            if (raw[i] == (byte)'\\' && raw[i + 1] == 0 && raw[i + 2] == (byte)'\\' && raw[i + 3] == 0) {
                StringBuilder sb = new StringBuilder();
                int j = i;
                while (j + 1 < end && sb.Length < 180) {
                    int ch = raw[j] | (raw[j + 1] << 8);
                    if (ch == 0) break;
                    if (ch >= 32 && ch < 127) sb.Append((char)ch);
                    j += 2;
                }
                if (sb.Length >= 4) return sb.ToString();
            }
        }
        return "";
    }

    static void ParseNtlm(SmbPacket p, byte[] raw, int start, int end) {
        int max = start + 900;
        if (max > end - 12) max = end - 12;
        for (int i = start; i < max; i++) {
            if (raw[i] == 0x4E && raw[i + 1] == 0x54 && raw[i + 2] == 0x4C && raw[i + 3] == 0x4D
                && raw[i + 4] == 0x53 && raw[i + 5] == 0x53 && raw[i + 6] == 0x50 && raw[i + 7] == 0x00) {
                int type = BitConverter.ToInt32(raw, i + 8);
                if (type == 1) p.Info += ", NTLMSSP_NEGOTIATE";
                else if (type == 2) p.Info += ", NTLMSSP_CHALLENGE";
                else if (type == 3) {
                    p.Info += ", NTLMSSP_AUTH";
                    string domain = ReadNtlmSecBuf(raw, i, 28, end);
                    string user = ReadNtlmSecBuf(raw, i, 36, end);
                    string ws = ReadNtlmSecBuf(raw, i, 44, end);
                    if (user.Length > 0) {
                        p.UserName = domain.Length > 0 ? domain + "\\" + user : user;
                        p.Info += ", User: " + p.UserName;
                    }
                    if (ws.Length > 0) {
                        p.Workstation = ws;
                        p.Info += ", WS: " + ws;
                    }
                }
                return;
            }
        }
    }

    static string ReadNtlmSecBuf(byte[] raw, int ntlmAt, int fieldOff, int end) {
        int at = ntlmAt + fieldOff;
        if (at + 8 > end) return "";
        int len = BitConverter.ToUInt16(raw, at);
        int off = BitConverter.ToInt32(raw, at + 4);
        if (len <= 0 || len > 256) return "";
        int abs = ntlmAt + off;
        if (abs < ntlmAt || abs + len > end) return "";
        bool unicode = true;
        for (int i = 0; i + 1 < len; i += 2) {
            if (raw[abs + i + 1] != 0) { unicode = false; break; }
        }
        string s = unicode ? Encoding.Unicode.GetString(raw, abs, len) : Encoding.ASCII.GetString(raw, abs, len);
        s = s.Replace("\0", "").Trim();
        StringBuilder clean = new StringBuilder();
        for (int i = 0; i < s.Length && clean.Length < 80; i++) {
            char c = s[i];
            if (c >= 32 && c < 127) clean.Append(c);
        }
        return clean.ToString();
    }

    static string FormatTcpInfo(SmbPacket p) {
        List<string> f = new List<string>();
        if ((p.TcpFlags & 0x02) != 0) f.Add("SYN");
        if ((p.TcpFlags & 0x10) != 0) f.Add("ACK");
        if ((p.TcpFlags & 0x01) != 0) f.Add("FIN");
        if ((p.TcpFlags & 0x04) != 0) f.Add("RST");
        if ((p.TcpFlags & 0x08) != 0) f.Add("PSH");
        if ((p.TcpFlags & 0x20) != 0) f.Add("URG");
        string flags = f.Count > 0 ? string.Join(",", f.ToArray()) : "NONE";
        return p.SrcPort + " -> " + p.DstPort + " [" + flags + "] Seq=" + p.Seq + " Ack=" + p.Ack
            + " Payload=" + p.PayloadLength;
    }

    static string Smb1CommandName(int c) {
        switch (c) {
            case 0x00: return "Create Directory";
            case 0x01: return "Delete Directory";
            case 0x02: return "Open";
            case 0x03: return "Create";
            case 0x04: return "Close";
            case 0x06: return "Delete";
            case 0x07: return "Rename";
            case 0x0A: return "Read";
            case 0x0B: return "Write";
            case 0x24: return "Locking AndX";
            case 0x25: return "Transaction";
            case 0x2B: return "Echo";
            case 0x2D: return "Open AndX";
            case 0x2E: return "Read AndX";
            case 0x2F: return "Write AndX";
            case 0x32: return "Transaction2";
            case 0x34: return "Find Close2";
            case 0x70: return "Tree Connect";
            case 0x71: return "Tree Disconnect";
            case 0x72: return "Negotiate Protocol";
            case 0x73: return "Session Setup AndX";
            case 0x74: return "Logoff AndX";
            case 0x75: return "Tree Connect AndX";
            case 0xA0: return "NT Trans";
            case 0xA2: return "NT Create AndX";
            case 0xA4: return "NT Cancel";
            case 0xA5: return "NT Rename";
            default: return "CMD 0x" + c.ToString("X2");
        }
    }

    static string Smb2CommandName(int c) {
        switch (c) {
            case 0x00: return "NEGOTIATE";
            case 0x01: return "SESSION_SETUP";
            case 0x02: return "LOGOFF";
            case 0x03: return "TREE_CONNECT";
            case 0x04: return "TREE_DISCONNECT";
            case 0x05: return "CREATE";
            case 0x06: return "CLOSE";
            case 0x07: return "FLUSH";
            case 0x08: return "READ";
            case 0x09: return "WRITE";
            case 0x0A: return "LOCK";
            case 0x0B: return "IOCTL";
            case 0x0C: return "CANCEL";
            case 0x0D: return "ECHO";
            case 0x0E: return "QUERY_DIRECTORY";
            case 0x0F: return "CHANGE_NOTIFY";
            case 0x10: return "QUERY_INFO";
            case 0x11: return "SET_INFO";
            case 0x12: return "OPLOCK_BREAK";
            default: return "CMD 0x" + c.ToString("X4");
        }
    }

    static string DialectHex(ushort d) {
        switch (d) {
            case 0x0202: return "SMB 2.0.2";
            case 0x0210: return "SMB 2.1";
            case 0x0300: return "SMB 3.0";
            case 0x0302: return "SMB 3.0.2";
            case 0x0311: return "SMB 3.1.1";
            default: return "0x" + d.ToString("X4");
        }
    }

    static string StatusName(uint s) {
        if (s == 0) return "SUCCESS";
        if (s == 0xC0000001) return "UNSUCCESSFUL";
        if (s == 0xC000000D) return "INVALID_PARAMETER";
        if (s == 0xC0000022) return "ACCESS_DENIED";
        if (s == 0xC0000034) return "OBJECT_NAME_NOT_FOUND";
        if (s == 0xC000003A) return "OBJECT_PATH_NOT_FOUND";
        if (s == 0xC000006D) return "LOGON_FAILURE";
        if (s == 0xC00000BB) return "NOT_SUPPORTED";
        if (s == 0xC0000002) return "NOT_IMPLEMENTED";
        if (s == 0xC0000070) return "INVALID_WORKSTATION";
        return "0x" + s.ToString("X8");
    }

    public static void WritePcap(string path, SmbPacket[] packets) {
        using (FileStream fs = File.Create(path))
        using (BinaryWriter bw = new BinaryWriter(fs)) {
            bw.Write(0xa1b2c3d4);
            bw.Write((ushort)2);
            bw.Write((ushort)4);
            bw.Write(0);
            bw.Write(0);
            bw.Write(65535);
            bw.Write(228);
            DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            for (int i = 0; i < packets.Length; i++) {
                SmbPacket p = packets[i];
                if (p == null || p.Raw == null) continue;
                long ticks = p.Time.ToUniversalTime().Ticks - epoch.Ticks;
                if (ticks < 0) ticks = 0;
                uint sec = (uint)(ticks / TimeSpan.TicksPerSecond);
                uint usec = (uint)((ticks % TimeSpan.TicksPerSecond) / 10);
                bw.Write(sec);
                bw.Write(usec);
                bw.Write(p.Raw.Length);
                bw.Write(p.Raw.Length);
                bw.Write(p.Raw);
            }
        }
    }

    public static SmbPacket[] ReadPcap(string path) {
        List<SmbPacket> list = new List<SmbPacket>();
        using (FileStream fs = File.OpenRead(path))
        using (BinaryReader br = new BinaryReader(fs)) {
            if (fs.Length < 24) return list.ToArray();
            uint magic = br.ReadUInt32();
            bool swap = magic == 0xd4c3b2a1;
            bool nsec = magic == 0xa1b23c4d || magic == 0x4d3cb2a1;
            if (magic != 0xa1b2c3d4 && magic != 0xd4c3b2a1 && magic != 0xa1b23c4d && magic != 0x4d3cb2a1)
                throw new InvalidDataException("Not a classic pcap file (unsupported magic).");
            ushort vmaj = br.ReadUInt16();
            ushort vmin = br.ReadUInt16();
            br.ReadInt32();
            br.ReadInt32();
            uint snap = br.ReadUInt32();
            uint network = br.ReadUInt32();
            if (swap) {
                vmaj = Swap16(vmaj);
                vmin = Swap16(vmin);
                snap = Swap32(snap);
                network = Swap32(network);
            }
            DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            while (fs.Position + 16 <= fs.Length) {
                uint tsSec = br.ReadUInt32();
                uint tsSub = br.ReadUInt32();
                uint incl = br.ReadUInt32();
                uint orig = br.ReadUInt32();
                if (swap) {
                    tsSec = Swap32(tsSec);
                    tsSub = Swap32(tsSub);
                    incl = Swap32(incl);
                    orig = Swap32(orig);
                }
                if (incl > 16 * 1024 * 1024) break;
                if (fs.Position + incl > fs.Length) break;
                byte[] frame = br.ReadBytes((int)incl);
                DateTime ts = epoch.AddSeconds(tsSec);
                if (nsec) ts = ts.AddTicks(tsSub / 100);
                else ts = ts.AddTicks(tsSub * 10);
                byte[] ip = ExtractIp(frame, network, swap);
                if (ip == null) continue;
                SmbPacket p = ParseIpPacket(ip, ts.ToLocalTime());
                if (p != null) list.Add(p);
            }
        }
        return list.ToArray();
    }

    static byte[] ExtractIp(byte[] frame, uint network, bool swap) {
        if (frame == null || frame.Length < 20) return null;
        uint link = network;
        if (link == 1 || link == 0) {
            if (frame.Length < 34) return null;
            int typeOff = 12;
            int etype = (frame[12] << 8) | frame[13];
            if (etype == 0x8100 && frame.Length >= 38) {
                typeOff = 16;
                etype = (frame[16] << 8) | frame[17];
            }
            if (etype != 0x0800) return null;
            int ipOff = typeOff + 2;
            int n = frame.Length - ipOff;
            byte[] ip = new byte[n];
            Buffer.BlockCopy(frame, ipOff, ip, 0, n);
            return ip;
        }
        if (link == 101 || link == 12 || link == 228 || link == 14) return frame;
        if (frame[0] == 0x45) return frame;
        return null;
    }

    static ushort Swap16(ushort v) { return (ushort)((v << 8) | (v >> 8)); }
    static uint Swap32(uint v) {
        return ((v & 0x000000FF) << 24) | ((v & 0x0000FF00) << 8)
             | ((v & 0x00FF0000) >> 8) | ((v & 0xFF000000) >> 24);
    }

    public static SmbPacket[] BuildDemoPackets() {
        List<SmbPacket> list = new List<SmbPacket>();
        DateTime t = DateTime.Now.AddSeconds(-8);
        string client = "10.10.50.88";
        string server = "10.10.50.10";
        string client2 = "10.10.51.17";

        list.Add(Wrap(BuildIpTcp(client, server, 55123, 445, 0x02, new byte[0]), t));
        t = t.AddMilliseconds(1);
        list.Add(Wrap(BuildIpTcp(server, client, 445, 55123, 0x12, new byte[0]), t));
        t = t.AddMilliseconds(1);
        list.Add(Wrap(BuildIpTcp(client, server, 55123, 445, 0x10, new byte[0]), t));

        t = t.AddMilliseconds(4);
        byte[] neg = BuildSmb1NegotiateRequest();
        list.Add(Wrap(BuildIpTcp(client, server, 55123, 445, 0x18, neg), t));

        t = t.AddMilliseconds(3);
        byte[] negR = BuildSmb1Header(0x72, true, 0, 0, 0, 1);
        list.Add(Wrap(BuildIpTcp(server, client, 445, 55123, 0x18, WithNetbios(Concat(negR, new byte[] { 17, 5, 0 }))), t));

        t = t.AddMilliseconds(6);
        byte[] sess = WithNetbios(Concat(BuildSmb1Header(0x73, false, 0, 1, 0, 2), BuildNtlmType3("CONTOSO", "legacyapp", "XPCLIENT01")));
        list.Add(Wrap(BuildIpTcp(client, server, 55123, 445, 0x18, sess), t));

        t = t.AddMilliseconds(5);
        byte[] tree = BuildSmb1TreeConnect("\\\\fileserver\\archive");
        list.Add(Wrap(BuildIpTcp(client, server, 55123, 445, 0x18, tree), t));

        t = t.AddMilliseconds(4);
        byte[] create = BuildSmb1NtCreate("\\oldapp\\data.mdb");
        list.Add(Wrap(BuildIpTcp(client, server, 55123, 445, 0x18, create), t));

        t = t.AddMilliseconds(80);
        byte[] smb2neg = BuildSmb2Negotiate();
        list.Add(Wrap(BuildIpTcp(client2, server, 49812, 445, 0x18, smb2neg), t));

        t = t.AddMilliseconds(12);
        byte[] neg2 = BuildSmb1NegotiateRequest();
        list.Add(Wrap(BuildIpTcp("192.168.88.19", server, 139, 445, 0x18, neg2), t));

        return list.ToArray();
    }

    static SmbPacket Wrap(byte[] raw, DateTime t) {
        SmbPacket p = ParseIpPacket(raw, t);
        if (p == null) {
            p = new SmbPacket();
            p.Raw = raw;
            p.Time = t;
            p.Length = raw.Length;
            p.Info = "parse-failed";
        }
        return p;
    }

    static byte[] BuildIpTcp(string src, string dst, int sp, int dp, byte flags, byte[] payload) {
        if (payload == null) payload = new byte[0];
        int total = 40 + payload.Length;
        byte[] raw = new byte[total];
        raw[0] = 0x45;
        raw[2] = (byte)(total >> 8);
        raw[3] = (byte)total;
        raw[8] = 128;
        raw[9] = 6;
        byte[] sb = IpBytes(src);
        byte[] db = IpBytes(dst);
        Array.Copy(sb, 0, raw, 12, 4);
        Array.Copy(db, 0, raw, 16, 4);
        raw[20] = (byte)(sp >> 8); raw[21] = (byte)sp;
        raw[22] = (byte)(dp >> 8); raw[23] = (byte)dp;
        raw[32] = 0x50;
        raw[33] = flags;
        raw[34] = 0x20; raw[35] = 0x00;
        if (payload.Length > 0) Array.Copy(payload, 0, raw, 40, payload.Length);
        return raw;
    }

    static byte[] IpBytes(string ip) {
        string[] p = ip.Split('.');
        return new byte[] { byte.Parse(p[0]), byte.Parse(p[1]), byte.Parse(p[2]), byte.Parse(p[3]) };
    }

    static byte[] WithNetbios(byte[] smb) {
        byte[] nb = new byte[4 + smb.Length];
        int n = smb.Length;
        nb[1] = (byte)((n >> 16) & 0xFF);
        nb[2] = (byte)((n >> 8) & 0xFF);
        nb[3] = (byte)(n & 0xFF);
        Array.Copy(smb, 0, nb, 4, smb.Length);
        return nb;
    }

    static byte[] BuildSmb1Header(byte cmd, bool reply, ushort tid, ushort pid, ushort uid, ushort mid) {
        byte[] h = new byte[32];
        h[0] = 0xFF; h[1] = 0x53; h[2] = 0x4D; h[3] = 0x42;
        h[4] = cmd;
        h[9] = reply ? (byte)0x98 : (byte)0x18;
        h[10] = 0x01; h[11] = 0xC8;
        BitConverter.GetBytes(tid).CopyTo(h, 24);
        BitConverter.GetBytes(pid).CopyTo(h, 26);
        BitConverter.GetBytes(uid).CopyTo(h, 28);
        BitConverter.GetBytes(mid).CopyTo(h, 30);
        return h;
    }

    static byte[] BuildSmb1NegotiateRequest() {
        string[] dialects = new string[] {
            "PC NETWORK PROGRAM 1.0", "LANMAN1.0", "Windows for Workgroups 3.1a",
            "LM1.2X002", "LANMAN2.1", "NT LM 0.12"
        };
        MemoryStream ms = new MemoryStream();
        for (int i = 0; i < dialects.Length; i++) {
            ms.WriteByte(0x02);
            byte[] name = Encoding.ASCII.GetBytes(dialects[i]);
            ms.Write(name, 0, name.Length);
            ms.WriteByte(0);
        }
        byte[] body = ms.ToArray();
        byte[] hdr = BuildSmb1Header(0x72, false, 0, 0, 0, 1);
        byte[] pkt = new byte[hdr.Length + 3 + body.Length];
        Array.Copy(hdr, 0, pkt, 0, hdr.Length);
        pkt[32] = 0;
        BitConverter.GetBytes((ushort)body.Length).CopyTo(pkt, 33);
        Array.Copy(body, 0, pkt, 35, body.Length);
        return WithNetbios(pkt);
    }

    static byte[] BuildSmb1TreeConnect(string path) {
        byte[] pathB = Encoding.ASCII.GetBytes(path);
        byte[] hdr = BuildSmb1Header(0x75, false, 0, 1, 1, 3);
        byte[] extra = new byte[1 + 2 + 1 + pathB.Length + 1];
        extra[0] = 0;
        BitConverter.GetBytes((ushort)(pathB.Length + 2)).CopyTo(extra, 1);
        extra[3] = 0;
        Array.Copy(pathB, 0, extra, 4, pathB.Length);
        return WithNetbios(Concat(hdr, extra));
    }

    static byte[] BuildSmb1NtCreate(string fileName) {
        byte[] fn = Encoding.ASCII.GetBytes(fileName);
        byte[] hdr = BuildSmb1Header(0xA2, false, 1, 1, 1, 4);
        byte[] extra = new byte[1 + 2 + fn.Length + 1];
        extra[0] = 0;
        BitConverter.GetBytes((ushort)(fn.Length + 1)).CopyTo(extra, 1);
        Array.Copy(fn, 0, extra, 3, fn.Length);
        extra[3 + fn.Length] = 0;
        return WithNetbios(Concat(hdr, extra));
    }

    static byte[] BuildNtlmType3(string domain, string user, string ws) {
        byte[] d = Encoding.Unicode.GetBytes(domain);
        byte[] u = Encoding.Unicode.GetBytes(user);
        byte[] w = Encoding.Unicode.GetBytes(ws);
        int ntlmLen = 64 + d.Length + u.Length + w.Length;
        byte[] ntlm = new byte[ntlmLen];
        byte[] sig = Encoding.ASCII.GetBytes("NTLMSSP");
        Array.Copy(sig, 0, ntlm, 0, sig.Length);
        BitConverter.GetBytes(3).CopyTo(ntlm, 8);
        int off = 64;
        WriteSecBuf(ntlm, 28, d, ref off);
        WriteSecBuf(ntlm, 36, u, ref off);
        WriteSecBuf(ntlm, 44, w, ref off);
        byte[] extra = new byte[3 + ntlm.Length];
        extra[0] = 0;
        BitConverter.GetBytes((ushort)ntlm.Length).CopyTo(extra, 1);
        Array.Copy(ntlm, 0, extra, 3, ntlm.Length);
        return extra;
    }

    static void WriteSecBuf(byte[] ntlm, int field, byte[] data, ref int off) {
        BitConverter.GetBytes((ushort)data.Length).CopyTo(ntlm, field);
        BitConverter.GetBytes((ushort)data.Length).CopyTo(ntlm, field + 2);
        BitConverter.GetBytes(off).CopyTo(ntlm, field + 4);
        Array.Copy(data, 0, ntlm, off, data.Length);
        off += data.Length;
    }

    static byte[] BuildSmb2Negotiate() {
        byte[] smb = new byte[64 + 36 + 10];
        smb[0] = 0xFE; smb[1] = 0x53; smb[2] = 0x4D; smb[3] = 0x42;
        smb[4] = 64;
        BitConverter.GetBytes((ushort)0).CopyTo(smb, 12);
        BitConverter.GetBytes((ushort)36).CopyTo(smb, 64);
        BitConverter.GetBytes((ushort)5).CopyTo(smb, 66);
        ushort[] ds = new ushort[] { 0x0202, 0x0210, 0x0300, 0x0302, 0x0311 };
        for (int i = 0; i < ds.Length; i++) BitConverter.GetBytes(ds[i]).CopyTo(smb, 64 + 36 + (i * 2));
        return WithNetbios(smb);
    }

    static byte[] Concat(byte[] a, byte[] b) {
        byte[] n = new byte[a.Length + b.Length];
        Array.Copy(a, 0, n, 0, a.Length);
        Array.Copy(b, 0, n, a.Length, b.Length);
        return n;
    }
}

public class SmbCaptureEngine {
    public ConcurrentQueue<SmbPacket> Queue = new ConcurrentQueue<SmbPacket>();
    public volatile bool Running;
    public volatile bool Paused;
    public volatile bool SmbPortsOnly = true;
    public volatile bool SmbPayloadOnly;
    public int Captured;
    public int Smb1Count;
    public int Smb2Count;
    public int Smb3Count;
    public int Dropped;
    public long Bytes;
    public string Error = "";
    public int MaxQueue = 25000;
    Socket _sock;
    Thread _thread;

    public bool Start(string localIp) {
        Error = "";
        try {
            IPAddress ip = IPAddress.Parse(localIp);
            _sock = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            _sock.Bind(new IPEndPoint(ip, 0));
            _sock.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
            byte[] inVal = BitConverter.GetBytes(1);
            byte[] outVal = new byte[4];
            _sock.IOControl(IOControlCode.ReceiveAll, inVal, outVal);
            _sock.ReceiveBufferSize = 2 * 1024 * 1024;
            _sock.ReceiveTimeout = 400;
            Running = true;
            Paused = false;
            _thread = new Thread(CaptureLoop);
            _thread.IsBackground = true;
            _thread.Name = "SmbCapture";
            _thread.Start();
            return true;
        } catch (Exception ex) {
            Error = ex.Message;
            Running = false;
            try { if (_sock != null) _sock.Close(); } catch { }
            return false;
        }
    }

    public void Stop() {
        Running = false;
        try { if (_sock != null) _sock.Close(); } catch { }
        _sock = null;
        try {
            if (_thread != null && _thread.IsAlive) _thread.Join(1500);
        } catch { }
        _thread = null;
    }

    public SmbPacket[] Drain(int max) {
        List<SmbPacket> list = new List<SmbPacket>(max);
        SmbPacket p;
        while (list.Count < max && Queue.TryDequeue(out p)) list.Add(p);
        return list.ToArray();
    }

    public CaptureStats GetStats() {
        CaptureStats s = new CaptureStats();
        s.Captured = Captured;
        s.Smb1 = Smb1Count;
        s.Smb2 = Smb2Count;
        s.Smb3 = Smb3Count;
        s.Dropped = Dropped;
        s.Queue = Queue.Count;
        s.Bytes = Bytes;
        return s;
    }

    void CaptureLoop() {
        byte[] buf = new byte[65535];
        while (Running) {
            int n = 0;
            try {
                n = _sock.Receive(buf);
            } catch (SocketException) {
                continue;
            } catch {
                break;
            }
            if (n < 20) continue;
            if (Paused) {
                Interlocked.Increment(ref Dropped);
                continue;
            }
            if (Queue.Count >= MaxQueue) {
                Interlocked.Increment(ref Dropped);
                continue;
            }
            byte[] raw = new byte[n];
            Buffer.BlockCopy(buf, 0, raw, 0, n);
            SmbPacket pkt = SmbPacketParser.ParseIpPacket(raw, DateTime.Now);
            if (pkt == null) continue;
            bool smbPort = pkt.SrcPort == 445 || pkt.DstPort == 445 || pkt.SrcPort == 139 || pkt.DstPort == 139;
            if (SmbPortsOnly && !smbPort) continue;
            if (SmbPayloadOnly && !pkt.HasSmb) continue;
            Interlocked.Increment(ref Captured);
            Interlocked.Add(ref Bytes, n);
            if (pkt.IsSmb1) Interlocked.Increment(ref Smb1Count);
            if (pkt.IsSmb2) Interlocked.Increment(ref Smb2Count);
            if (pkt.IsSmb3) Interlocked.Increment(ref Smb3Count);
            Queue.Enqueue(pkt);
        }
    }
}
'@
    try {
        Add-Type -TypeDefinition $cs -Language CSharp -ErrorAction Stop
    } catch {
        throw "Failed to compile the packet engine (needs .NET Framework 4.5+ / Windows PowerShell 5.1): $($_.Exception.Message)"
    }
}

# ============================================================
# SELF-TEST (no GUI)
# ============================================================
function Invoke-SmbAnalyzerSelfTest {
    $failures = New-Object System.Collections.Generic.List[string]
    $demo = [SmbPacketParser]::BuildDemoPackets()
    if ($demo.Length -lt 8) { [void]$failures.Add("Demo packet count $($demo.Length) < 8") }

    $smb1 = $demo | Where-Object { $_.IsSmb1 }
    if (-not $smb1) { [void]$failures.Add("No SMBv1 packets in demo set") }

    $neg = $demo | Where-Object { $_.IsSmb1 -and $_.IsNegotiate -and $_.Info -match 'Request' } | Select-Object -First 1
    if (-not $neg) {
        [void]$failures.Add("SMB1 Negotiate Request missing")
    } else {
        if ($neg.Dialects -notmatch 'NT LM 0\.12') { [void]$failures.Add("NT LM 0.12 dialect not parsed: $($neg.Dialects)") }
        if ($neg.SmbOffset -lt 0) { [void]$failures.Add("SMB magic offset not set") }
        if ($neg.Protocol -ne 'SMB1') { [void]$failures.Add("Protocol=$($neg.Protocol)") }
    }

    $auth = $demo | Where-Object { $_.UserName -match 'legacyapp' } | Select-Object -First 1
    if (-not $auth) { [void]$failures.Add("NTLM Type 3 username not parsed") }

    $tree = $demo | Where-Object { $_.SharePath -match 'archive' } | Select-Object -First 1
    if (-not $tree) { [void]$failures.Add("Tree connect path not parsed") }

    $smb2 = $demo | Where-Object { $_.Protocol -eq 'SMB2' -and $_.IsNegotiate } | Select-Object -First 1
    if (-not $smb2) { [void]$failures.Add("SMB2 negotiate demo packet missing") }

    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("smb1-selftest-{0}.pcap" -f [guid]::NewGuid().ToString('N'))
    try {
        [SmbPacketParser]::WritePcap($tmp, $demo)
        $round = [SmbPacketParser]::ReadPcap($tmp)
        if ($round.Length -ne $demo.Length) {
            [void]$failures.Add("PCAP round-trip count $($round.Length) != $($demo.Length)")
        }
        $r1 = $round | Where-Object { $_.IsSmb1 -and $_.IsNegotiate } | Select-Object -First 1
        if (-not $r1) { [void]$failures.Add("PCAP reload lost SMBv1 negotiate") }
    } catch {
        [void]$failures.Add("PCAP I/O: $($_.Exception.Message)")
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }

    $crafted = [byte[]]@(
        0x45,0x00,0x00,0x4C,0x00,0x00,0x00,0x00,0x40,0x06,0x00,0x00,
        10,1,1,8, 10,1,1,1,
        0xC0,0x00, 0x01,0xBD, 0,0,0,1, 0,0,0,0, 0x50,0x18,0x20,0x00,0,0,0,0,
        0x00,0x00,0x00,0x20,
        0xFF,0x53,0x4D,0x42, 0x72, 0,0,0,0, 0x18, 0x01,0xC8, 0,0,
        0,0,0,0,0,0,0,0, 0,0, 0,0, 0,0, 0,0, 0,0
    )
    $p = [SmbPacketParser]::ParseIpPacket($crafted, [datetime]::UtcNow)
    if (-not $p -or -not $p.IsSmb1 -or $p.SmbCommandCode -ne 0x72) {
        [void]$failures.Add("Hand-crafted SMB1 negotiate parse failed")
    }
    if (-not $p -or $p.Src -ne '10.1.1.8' -or $p.DstPort -ne 445) {
        [void]$failures.Add("IP/TCP parse failed for crafted frame")
    }

    if ($failures.Count -gt 0) {
        Write-Host "SELFTEST FAIL ($($failures.Count))" -ForegroundColor Red
        $failures | ForEach-Object { Write-Host " - $_" -ForegroundColor Red }
        return 1
    }
    Write-Host "SELFTEST PASS  demo=$($demo.Length) packets  smb1=$((@($smb1)).Count)  pcap round-trip ok" -ForegroundColor Green
    return 0
}

if ($SelfTest) {
    $code = Invoke-SmbAnalyzerSelfTest
    exit $code
}

# ============================================================
# WINFORMS
# ============================================================
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
[System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)

# ============================================================
# STATE
# ============================================================
$script:Engine          = New-Object SmbCaptureEngine
$script:AllPackets      = New-Object 'System.Collections.Generic.List[SmbPacket]'
$script:ViewPackets     = New-Object 'System.Collections.Generic.List[SmbPacket]'
$script:Smb1Hosts       = @{}
$script:Smb1CommandHist = @{}
$script:NextNo          = 1
$script:MaxPackets      = 25000
$script:IsAdmin         = $false
$script:CaptureStarted  = $null
$script:SortColumn      = 0
$script:SortAscending   = $true
$script:FindIndex       = -1
$script:LastBannerCount = 0
$script:UiBusy          = $false
$script:FilterText      = ''
$script:txtLog          = $null
$script:lvPackets       = $null
$script:txtFilter       = $null
$script:chkSmb1Only     = $null
$script:chkAutoScroll   = $null
$script:banner          = $null
$script:MainForm        = $null

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    $script:IsAdmin = $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $script:IsAdmin = $false
}

# ============================================================
# COLORS
# ============================================================
$script:C = @{
    Header     = [System.Drawing.Color]::FromArgb(24, 42, 68)
    Header2    = [System.Drawing.Color]::FromArgb(32, 52, 80)
    Bg         = [System.Drawing.Color]::FromArgb(245, 247, 250)
    Split      = [System.Drawing.Color]::FromArgb(220, 225, 232)
    Text       = [System.Drawing.Color]::FromArgb(24, 42, 68)
    White      = [System.Drawing.Color]::White
    Blue       = [System.Drawing.Color]::FromArgb(0, 120, 212)
    Green      = [System.Drawing.Color]::FromArgb(16, 137, 62)
    Red        = [System.Drawing.Color]::FromArgb(196, 43, 28)
    Orange     = [System.Drawing.Color]::FromArgb(202, 131, 0)
    Teal       = [System.Drawing.Color]::FromArgb(0, 150, 136)
    Gray       = [System.Drawing.Color]::FromArgb(100, 110, 125)
    Dark       = [System.Drawing.Color]::FromArgb(55, 65, 81)
    Smb1       = [System.Drawing.Color]::FromArgb(255, 205, 205)
    Smb1Neg    = [System.Drawing.Color]::FromArgb(255, 170, 170)
    Smb2       = [System.Drawing.Color]::FromArgb(205, 228, 255)
    Smb3       = [System.Drawing.Color]::FromArgb(205, 245, 220)
    Tcp        = [System.Drawing.Color]::FromArgb(248, 249, 251)
    Marked     = [System.Drawing.Color]::FromArgb(255, 236, 179)
    AlertBg    = [System.Drawing.Color]::FromArgb(153, 27, 27)
    OkGreen    = [System.Drawing.Color]::FromArgb(0, 210, 106)
}

# ============================================================
# HELPERS
# ============================================================
function Get-Timestamp { Get-Date -Format 'yyyy-MM-dd HH:mm:ss' }

function Write-AppLog {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '[{0}] [{1}] {2}' -f (Get-Timestamp), $Level, $Message
    if ($script:txtLog) {
        $script:txtLog.AppendText($line + [Environment]::NewLine)
        $script:txtLog.SelectionStart = $script:txtLog.Text.Length
        $script:txtLog.ScrollToCaret()
    }
}

function Test-IsAdministrator { [bool]$script:IsAdmin }

function Get-CaptureInterfaces {
    $items = New-Object System.Collections.Generic.List[object]
    try {
        Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop | ForEach-Object {
            $desc = $_.Description
            foreach ($ip in @($_.IPAddress)) {
                if ($ip -match '^\d+\.\d+\.\d+\.\d+$') {
                    [void]$items.Add([pscustomobject]@{
                        Display = '{0}   ({1})' -f $ip, $desc
                        IP      = $ip
                    })
                }
            }
        }
    } catch {
        Write-AppLog "Adapter enumeration failed: $($_.Exception.Message)" 'ERROR'
    }
    return $items
}

function New-FlatButton {
    param(
        [string]$Text,
        [int]$Width,
        [int]$Height = 30,
        [System.Drawing.Color]$BackColor,
        [scriptblock]$OnClick,
        [string]$TipText = '',
        [bool]$Bold = $true
    )
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $Text
    $b.Size = New-Object System.Drawing.Size($Width, $Height)
    $b.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $b.BackColor = $BackColor
    $b.ForeColor = $script:C.White
    $style = if ($Bold) { [System.Drawing.FontStyle]::Bold } else { [System.Drawing.FontStyle]::Regular }
    $b.Font = New-Object System.Drawing.Font('Segoe UI', 9, $style)
    $b.FlatAppearance.BorderSize = 0
    $b.Cursor = [System.Windows.Forms.Cursors]::Hand
    $b.Margin = New-Object System.Windows.Forms.Padding(0, 0, 6, 0)
    if ($OnClick) { $b.Add_Click($OnClick) }
    if ($TipText -and $script:Tip) { $script:Tip.SetToolTip($b, $TipText) }
    return $b
}

function Enable-DoubleBuffer {
    param($Control)
    try {
        $prop = $Control.GetType().GetProperty('DoubleBuffered', [Reflection.BindingFlags]'NonPublic,Instance')
        if ($prop) { $prop.SetValue($Control, $true, $null) }
    } catch { }
}

function Get-PacketRowColor {
    param([SmbPacket]$p)
    if ($p.Marked) { return $script:C.Marked }
    if ($p.IsSmb1 -and $p.IsNegotiate) { return $script:C.Smb1Neg }
    if ($p.IsSmb1) { return $script:C.Smb1 }
    if ($p.Protocol -eq 'SMB3' -or $p.IsSmb3) { return $script:C.Smb3 }
    if ($p.IsSmb2 -or $p.Protocol -eq 'SMB2') { return $script:C.Smb2 }
    return $script:C.Tcp
}

function Test-FilterToken {
    param([SmbPacket]$pkt, [string]$Token)
    $t = $Token.Trim()
    if ($t.Length -eq 0) { return $true }
    if ($t -match '^(?i)not\s+(.+)$') { return -not (Test-FilterToken $pkt $Matches[1]) }

    $tl = $t.ToLowerInvariant()
    switch -regex ($tl) {
        '^(smb1|smbv1|smb\.v1)$' { return [bool]$pkt.IsSmb1 }
        '^(smb2|smbv2)$'         { return [bool]($pkt.IsSmb2 -or $pkt.Protocol -eq 'SMB2') }
        '^(smb3|smbv3)$'         { return [bool]($pkt.IsSmb3 -or $pkt.Protocol -eq 'SMB3') }
        '^smb$'                  { return [bool]$pkt.HasSmb }
        '^tcp$'                  { return $pkt.Protocol -eq 'TCP' }
        '^marked$'               { return [bool]$pkt.Marked }
        '^(negotiate|neg)$'      { return [bool]$pkt.IsNegotiate }
        '^(session|sess|setup)$' { return [bool]$pkt.IsSessionSetup }
        '^(tree|tcon)$'          { return [bool]$pkt.IsTreeConnect }
        '^(create|ntcreate|open)$' { return [bool]$pkt.IsNtCreate }
        '^(syn)$'                { return ($pkt.TcpFlags -band 0x02) -ne 0 -and -not $pkt.HasSmb }
        default { }
    }

    if ($tl -match '^stream\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\d+\.\d+\.\d+\.\d+):(\d+)$') {
        $a = $Matches[1]; $ap = [int]$Matches[2]; $b = $Matches[3]; $bp = [int]$Matches[4]
        return (($pkt.Src -eq $a -and $pkt.SrcPort -eq $ap -and $pkt.Dst -eq $b -and $pkt.DstPort -eq $bp) -or
                ($pkt.Src -eq $b -and $pkt.SrcPort -eq $bp -and $pkt.Dst -eq $a -and $pkt.DstPort -eq $ap))
    }
    if ($tl -match '^(ip\.addr|host)\s*(==|=)\s*(\d+\.\d+\.\d+\.\d+)$') {
        $ip = $Matches[3]; return ($pkt.Src -eq $ip -or $pkt.Dst -eq $ip)
    }
    if ($tl -match '^ip\.src\s*(==|=)\s*(\d+\.\d+\.\d+\.\d+)$') { return $pkt.Src -eq $Matches[2] }
    if ($tl -match '^ip\.dst\s*(==|=)\s*(\d+\.\d+\.\d+\.\d+)$') { return $pkt.Dst -eq $Matches[2] }
    if ($tl -match '^tcp\.port\s*(==|=)\s*(\d+)$') {
        $port = [int]$Matches[2]; return ($pkt.SrcPort -eq $port -or $pkt.DstPort -eq $port)
    }
    if ($tl -match '^tcp\.srcport\s*(==|=)\s*(\d+)$') { return $pkt.SrcPort -eq [int]$Matches[2] }
    if ($tl -match '^tcp\.dstport\s*(==|=)\s*(\d+)$') { return $pkt.DstPort -eq [int]$Matches[2] }
    if ($tl -match '^smb\.cmd\s*(==|=)\s*(0x[0-9a-f]+|\d+)$') {
        $n = [int]($Matches[2]); return $pkt.SmbCommandCode -eq $n
    }
    if ($tl -match '^user:(.+)$') {
        return ($pkt.UserName -and $pkt.UserName.ToLowerInvariant().Contains($Matches[1]))
    }
    if ($tl -match '^file:(.+)$') {
        return ($pkt.FileName -and $pkt.FileName.ToLowerInvariant().Contains($Matches[1]))
    }
    if ($tl -match '^contains:(.+)$') {
        return ($pkt.Info -and $pkt.Info.ToLowerInvariant().Contains($Matches[1]))
    }
    if ($tl -match '^\d+\.\d+\.\d+\.\d+$') { return ($pkt.Src -eq $t -or $pkt.Dst -eq $t) }
    if ($tl -match '^:(\d+)$' -or $tl -match '^(139|445)$') {
        $port = [int]($Matches[1]); return ($pkt.SrcPort -eq $port -or $pkt.DstPort -eq $port)
    }
    if ($pkt.Info -and $pkt.Info.ToLowerInvariant().Contains($tl)) { return $true }
    if ($pkt.SmbCommand -and $pkt.SmbCommand.ToLowerInvariant().Contains($tl)) { return $true }
    if ($pkt.UserName -and $pkt.UserName.ToLowerInvariant().Contains($tl)) { return $true }
    return $false
}

function Test-PacketFilter {
    param([SmbPacket]$pkt)
    if ($script:chkSmb1Only -and $script:chkSmb1Only.Checked -and -not $pkt.IsSmb1) { return $false }
    $f = $script:FilterText
    if ([string]::IsNullOrWhiteSpace($f)) { return $true }
    $opt = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    $parts = [regex]::Split($f.Trim(), '\s+and\s+|\s+&&\s+', $opt)
    foreach ($part in $parts) {
        $orParts = [regex]::Split($part.Trim(), '\s+or\s+|\s+\|\|\s+', $opt)
        $ok = $false
        foreach ($op in $orParts) {
            if (Test-FilterToken $pkt $op) { $ok = $true; break }
        }
        if (-not $ok) { return $false }
    }
    return $true
}

function Update-PacketView {
    $script:FilterText = if ($script:txtFilter) { $script:txtFilter.Text } else { '' }
    $script:ViewPackets.Clear()
    foreach ($p in $script:AllPackets) {
        if (Test-PacketFilter $p) { [void]$script:ViewPackets.Add($p) }
    }
    if ($script:lvPackets) {
        $script:lvPackets.VirtualListSize = $script:ViewPackets.Count
        $script:lvPackets.Invalidate()
    }
    Update-FilterBoxColor
    Update-StatusBar
}

function Update-FilterBoxColor {
    if (-not $script:txtFilter) { return }
    $t = $script:txtFilter.Text.Trim()
    if ($t.Length -eq 0) {
        $script:txtFilter.BackColor = $script:C.White
        return
    }
    $script:txtFilter.BackColor = [System.Drawing.Color]::FromArgb(220, 255, 220)
}

function Limit-PacketBuffer {
    if ($script:AllPackets.Count -le $script:MaxPackets) { return }
    $trim = [Math]::Max(500, [int]($script:MaxPackets * 0.15))
    $script:AllPackets.RemoveRange(0, $trim)
    Update-PacketView
    Write-AppLog "Packet buffer trimmed by $trim frames (cap=$($script:MaxPackets))." 'WARN'
}

function Get-Smb1Peer {
    param([SmbPacket]$pkt)
    if ($pkt.DstPort -eq 445 -or $pkt.DstPort -eq 139) {
        return @{ Client = $pkt.Src; Server = $pkt.Dst }
    }
    if ($pkt.SrcPort -eq 445 -or $pkt.SrcPort -eq 139) {
        return @{ Client = $pkt.Dst; Server = $pkt.Src }
    }
    return @{ Client = $pkt.Src; Server = $pkt.Dst }
}

function Update-Smb1Host {
    param([SmbPacket]$pkt)
    if (-not $pkt.IsSmb1) { return }
    $peer = Get-Smb1Peer $pkt
    foreach ($pair in @(@($peer.Client, 'Client'), @($peer.Server, 'Server'))) {
        $ip = $pair[0]; $role = $pair[1]
        if (-not $script:Smb1Hosts.ContainsKey($ip)) {
            $script:Smb1Hosts[$ip] = @{
                IP          = $ip
                HostName    = ''
                Role        = $role
                Packets     = 0
                FirstSeen   = $pkt.Time
                LastSeen    = $pkt.Time
                Commands    = @{}
                Users       = New-Object System.Collections.Generic.List[string]
                Shares      = New-Object System.Collections.Generic.List[string]
                Files       = New-Object System.Collections.Generic.List[string]
                Sample      = $pkt.Info
            }
        }
        $h = $script:Smb1Hosts[$ip]
        $h.Packets++
        $h.LastSeen = $pkt.Time
        if ($h.Role -ne $role -and $h.Role -ne 'Both') { $h.Role = 'Both' }
        $cmd = $pkt.SmbCommand
        if ($cmd) {
            if ($h.Commands.ContainsKey($cmd)) { $h.Commands[$cmd]++ } else { $h.Commands[$cmd] = 1 }
            if ($script:Smb1CommandHist.ContainsKey($cmd)) { $script:Smb1CommandHist[$cmd]++ } else { $script:Smb1CommandHist[$cmd] = 1 }
        }
        if ($pkt.UserName -and -not $h.Users.Contains($pkt.UserName)) { [void]$h.Users.Add($pkt.UserName) }
        if ($pkt.SharePath -and -not $h.Shares.Contains($pkt.SharePath)) { [void]$h.Shares.Add($pkt.SharePath) }
        if ($pkt.FileName -and -not $h.Files.Contains($pkt.FileName)) { [void]$h.Files.Add($pkt.FileName) }
        $h.Sample = $pkt.Info
    }
}

function Add-PacketsToUi {
    param([SmbPacket[]]$Packets)
    if (-not $Packets -or $Packets.Length -eq 0) { return 0 }
    $added = 0
    foreach ($pkt in $Packets) {
        $pkt.No = $script:NextNo
        $script:NextNo++
        [void]$script:AllPackets.Add($pkt)
        if (Test-PacketFilter $pkt) { [void]$script:ViewPackets.Add($pkt) }
        if ($pkt.IsSmb1) { Update-Smb1Host $pkt }
        $added++
    }
    return $added
}

function Refresh-PacketListView {
    param([switch]$ScrollEnd)
    if (-not $script:lvPackets) { return }
    $script:lvPackets.VirtualListSize = $script:ViewPackets.Count
    if ($ScrollEnd -and $script:chkAutoScroll -and $script:chkAutoScroll.Checked -and $script:ViewPackets.Count -gt 0) {
        try { $script:lvPackets.EnsureVisible($script:ViewPackets.Count - 1) } catch { }
    } else {
        $script:lvPackets.Invalidate()
    }
}

function Update-StatusBar {
    $stats = $null
    if ($script:Engine) { $stats = $script:Engine.GetStats() }
    $smb1View = 0
    foreach ($p in $script:ViewPackets) { if ($p.IsSmb1) { $smb1View++ } }
    $elapsed = ''
    if ($script:CaptureStarted) {
        $ts = (Get-Date) - $script:CaptureStarted
        $elapsed = '{0:00}:{1:00}:{2:00}' -f [int]$ts.TotalHours, $ts.Minutes, $ts.Seconds
    }
    $state = 'Idle'
    if ($script:Engine.Running -and $script:Engine.Paused) { $state = 'Paused' }
    elseif ($script:Engine.Running) { $state = 'Capturing' }

    if ($script:lblState) { $script:lblState.Text = $state }
    if ($script:lblPkt) {
        $cap = if ($stats) { $stats.Captured } else { 0 }
        $script:lblPkt.Text = 'Packets: {0}   Shown: {1}' -f $script:AllPackets.Count, $script:ViewPackets.Count
        if ($cap -gt 0 -and $script:AllPackets.Count -ne $cap) {
            $script:lblPkt.Text = 'Packets: {0} (engine {1})   Shown: {2}' -f $script:AllPackets.Count, $cap, $script:ViewPackets.Count
        }
    }
    if ($script:lblSmb1) {
        $eng1 = if ($stats) { $stats.Smb1 } else { 0 }
        $script:lblSmb1.Text = 'SMBv1: {0}' -f $eng1
        $script:lblSmb1.ForeColor = if ($eng1 -gt 0) { [System.Drawing.Color]::FromArgb(255, 180, 180) } else { [System.Drawing.Color]::FromArgb(180, 200, 180) }
    }
    if ($script:lblDrop) {
        $d = if ($stats) { $stats.Dropped } else { 0 }
        $script:lblDrop.Text = 'Dropped: {0}' -f $d
    }
    if ($script:lblElapsed) { $script:lblElapsed.Text = if ($elapsed) { "Elapsed: $elapsed" } else { 'Elapsed: --' } }
    if ($script:lblHosts) { $script:lblHosts.Text = 'SMBv1 hosts: {0}' -f $script:Smb1Hosts.Count }

    if ($script:banner -and $stats) {
        if ($stats.Smb1 -gt 0) {
            $script:banner.Visible = $true
            $script:banner.Text = "  SMBv1 DETECTED  -  $($stats.Smb1) SMBv1 packet(s), $($script:Smb1Hosts.Count) host(s). This dialect is deprecated and insecure."
            if ($stats.Smb1 -gt $script:LastBannerCount -and $script:LastBannerCount -eq 0) {
                Write-AppLog "First SMBv1 packet observed on the wire." 'WARN'
            }
            $script:LastBannerCount = $stats.Smb1
        }
    }
}

function Update-CaptureUi {
    if ($script:UiBusy) { return }
    $script:UiBusy = $true
    try {
        if ($script:Engine -and $script:Engine.Running) {
            $batch = $script:Engine.Drain(120)
            if ($batch.Length -gt 0) {
                [void](Add-PacketsToUi -Packets $batch)
                Refresh-PacketListView -ScrollEnd
                if ($script:AllPackets.Count -gt $script:MaxPackets) { Limit-PacketBuffer }
            }
        }
        Update-StatusBar
        if ($script:tabMain -and $script:tabMain.SelectedTab -eq $script:tabStats) { Update-StatsTab }
        if ($script:tabMain -and $script:tabMain.SelectedTab -eq $script:tabHosts) { Update-HostsGrid }
    } catch {
        Write-AppLog "UI update error: $($_.Exception.Message)" 'ERROR'
    } finally {
        $script:UiBusy = $false
    }
}

function Show-PacketDetails {
    param([SmbPacket]$p)
    $script:tvDetails.BeginUpdate()
    $script:tvDetails.Nodes.Clear()
    $script:hexBox.Clear()
    if (-not $p) { $script:tvDetails.EndUpdate(); return }

    $frame = $script:tvDetails.Nodes.Add(("Frame {0}: {1} bytes  {2}" -f $p.No, $p.Length, $p.Time.ToString('yyyy-MM-dd HH:mm:ss.fff')))
    [void]$frame.Nodes.Add("Marked: $($p.Marked)")
    [void]$frame.Nodes.Add("Protocol column: $($p.Protocol)")

    $ip = $frame.Nodes.Add(("Internet Protocol Version 4, Src: {0}, Dst: {1}" -f $p.Src, $p.Dst))
    [void]$ip.Nodes.Add("Header length: $($p.IpHeaderLen)")
    [void]$ip.Nodes.Add("Source: $($p.Src)")
    [void]$ip.Nodes.Add("Destination: $($p.Dst)")

    $flags = @()
    if (($p.TcpFlags -band 0x02) -ne 0) { $flags += 'SYN' }
    if (($p.TcpFlags -band 0x10) -ne 0) { $flags += 'ACK' }
    if (($p.TcpFlags -band 0x01) -ne 0) { $flags += 'FIN' }
    if (($p.TcpFlags -band 0x04) -ne 0) { $flags += 'RST' }
    if (($p.TcpFlags -band 0x08) -ne 0) { $flags += 'PSH' }
    if (($p.TcpFlags -band 0x20) -ne 0) { $flags += 'URG' }
    $tcp = $frame.Nodes.Add(("Transmission Control Protocol, Src Port: {0}, Dst Port: {1}, Flags: [{2}]" -f $p.SrcPort, $p.DstPort, ($flags -join ',')))
    [void]$tcp.Nodes.Add("Source Port: $($p.SrcPort)")
    [void]$tcp.Nodes.Add("Destination Port: $($p.DstPort)")
    [void]$tcp.Nodes.Add("Sequence: $($p.Seq)")
    [void]$tcp.Nodes.Add("Acknowledgment: $($p.Ack)")
    [void]$tcp.Nodes.Add("Header length: $($p.TcpHeaderLen)")
    [void]$tcp.Nodes.Add("Payload length: $($p.PayloadLength)")
    [void]$tcp.Nodes.Add("Payload offset in frame: $($p.PayloadOffset)")

    if ($p.PayloadLength -ge 4 -and $p.Raw -and $p.PayloadOffset -ge 0 -and ($p.PayloadOffset + 3) -lt $p.Raw.Length) {
        $nb0 = $p.Raw[$p.PayloadOffset]
        $nbLen = ($p.Raw[$p.PayloadOffset+1] -shl 16) -bor ($p.Raw[$p.PayloadOffset+2] -shl 8) -bor $p.Raw[$p.PayloadOffset+3]
        $nb = $frame.Nodes.Add(("NetBIOS Session Service  Type=0x{0:X2}  Length={1}" -f $nb0, $nbLen))
        [void]$nb.Nodes.Add("Type: $(if ($nb0 -eq 0) { 'Session message (0x00)' } else { '0x{0:X2}' -f $nb0 })")
    }

    if ($p.HasSmb) {
        $smbTitle = if ($p.IsSmb1) { 'SMB (Server Message Block Protocol)  [SMBv1 - INSECURE]' } else { $p.SmbVersion }
        $smb = $frame.Nodes.Add($smbTitle)
        [void]$smb.Nodes.Add("Version: $($p.SmbVersion)")
        [void]$smb.Nodes.Add("Command: $($p.SmbCommand) (0x$('{0:X2}' -f $p.SmbCommandCode))")
        [void]$smb.Nodes.Add("NT Status: $($p.NtStatus) (0x$('{0:X8}' -f $p.NtStatus))")
        [void]$smb.Nodes.Add("TID=$($p.Tid)  PID=$($p.Pid)  UID=$($p.Uid)  MID=$($p.Mid)")
        [void]$smb.Nodes.Add("SMB header offset: $($p.SmbOffset)")
        if ($p.Dialects) { [void]$smb.Nodes.Add("Dialects: $($p.Dialects)") }
        if ($p.UserName) { [void]$smb.Nodes.Add("User: $($p.UserName)") }
        if ($p.Workstation) { [void]$smb.Nodes.Add("Workstation: $($p.Workstation)") }
        if ($p.SharePath) { [void]$smb.Nodes.Add("Tree: $($p.SharePath)") }
        if ($p.FileName) { [void]$smb.Nodes.Add("File: $($p.FileName)") }
        [void]$smb.Nodes.Add("Summary: $($p.Info)")
        if ($p.IsSmb1) {
            $warn = $smb.Nodes.Add("SECURITY: SMBv1 has no modern encryption, is vulnerable to relay and downgrade attacks, and is disabled by default on current Windows.")
            $warn.ForeColor = $script:C.Red
        }
    }

    $frame.Expand()
    foreach ($n in $frame.Nodes) { $n.Expand() }
    $script:tvDetails.EndUpdate()
    Set-HexDump -Packet $p
}

function Set-HexDump {
    param([SmbPacket]$Packet)
    $box = $script:hexBox
    $box.Clear()
    if (-not $Packet -or -not $Packet.Raw) { return }
    $bytes = $Packet.Raw
    $hi = $Packet.SmbOffset
    $hiLen = if ($Packet.IsSmb1) { 4 } elseif ($Packet.HasSmb) { 4 } else { 0 }

    $sb = New-Object System.Text.StringBuilder
    $highlightRanges = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $bytes.Length; $i += 16) {
        [void]$sb.AppendFormat('{0:X4}  ', $i)
        $chunk = New-Object System.Text.StringBuilder
        $ascii = New-Object System.Text.StringBuilder
        $n = [Math]::Min(16, $bytes.Length - $i)
        for ($j = 0; $j -lt 16; $j++) {
            if ($j -eq 8) { [void]$chunk.Append(' ') }
            if ($j -lt $n) {
                $b = $bytes[$i + $j]
                $abs = $i + $j
                $hexStr = '{0:X2} ' -f $b
                if ($hiLen -gt 0 -and $abs -ge $hi -and $abs -lt ($hi + $hiLen)) {
                    [void]$highlightRanges.Add([pscustomobject]@{ Start = $sb.Length + $chunk.Length; Length = 3 })
                }
                [void]$chunk.Append($hexStr)
                $ch = if ($b -ge 32 -and $b -le 126) { [char]$b } else { '.' }
                [void]$ascii.Append($ch)
            } else {
                [void]$chunk.Append('   ')
                [void]$ascii.Append(' ')
            }
        }
        [void]$sb.Append($chunk.ToString())
        [void]$sb.Append(' | ')
        [void]$sb.AppendLine($ascii.ToString())
    }
    $box.Text = $sb.ToString()
    $box.SelectAll()
    $box.SelectionColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $box.DeselectAll()
    foreach ($r in $highlightRanges) {
        if ($r.Start -ge 0 -and ($r.Start + $r.Length) -le $box.TextLength) {
            $box.Select($r.Start, $r.Length)
            $box.SelectionColor = $script:C.Red
            $box.SelectionFont = New-Object System.Drawing.Font('Consolas', 9, [System.Drawing.FontStyle]::Bold)
        }
    }
    $box.DeselectAll()
    $box.SelectionStart = 0
}

function Get-SelectedPacket {
    if (-not $script:lvPackets -or $script:lvPackets.SelectedIndices.Count -eq 0) { return $null }
    $idx = $script:lvPackets.SelectedIndices[0]
    if ($idx -lt 0 -or $idx -ge $script:ViewPackets.Count) { return $null }
    return $script:ViewPackets[$idx]
}

function Start-Capture {
    if (-not $script:IsAdmin) {
        [void][System.Windows.Forms.MessageBox]::Show(
            "Live capture requires an elevated Administrator PowerShell session.`n`nRight-click powershell.exe -> Run as administrator, then relaunch this script.`n`nYou can still open a PCAP, load the demo capture, inspect SMB configuration, and scan event logs.",
            'Administrator Required',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    if ($script:Engine.Running) { return }
    $item = $script:cmbIface.SelectedItem
    if (-not $item) {
        [void][System.Windows.Forms.MessageBox]::Show('Select a capture interface (local IPv4 address).', 'No Interface', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        return
    }
    $ip = $item.IP
    $script:Engine.SmbPortsOnly = $script:chkPortsOnly.Checked
    $script:Engine.SmbPayloadOnly = $script:chkSmbPayload.Checked
    Write-AppLog "Starting capture on $ip (SMB ports only=$($script:Engine.SmbPortsOnly))" 'INFO'
    $ok = $script:Engine.Start($ip)
    if (-not $ok) {
        [void][System.Windows.Forms.MessageBox]::Show(
            "Failed to start raw-socket capture on $ip.`n`n$($script:Engine.Error)`n`nTypical causes:`n - Not running as Administrator`n - Windows Firewall / WFP blocking raw sockets`n - Interface has no IPv4 address`n`nYou can still File > Open PCAP or load the built-in demo capture.",
            'Capture Failed',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error)
        Write-AppLog "Capture start failed: $($script:Engine.Error)" 'ERROR'
        return
    }
    $script:CaptureStarted = Get-Date
    $script:btnStart.Enabled = $false
    $script:btnStop.Enabled = $true
    $script:btnPause.Enabled = $true
    $script:cmbIface.Enabled = $false
    Write-AppLog "Capture running on $ip." 'SUCCESS'
}

function Stop-Capture {
    if ($script:Engine.Running) {
        $script:Engine.Stop()
        Write-AppLog 'Capture stopped.' 'INFO'
    }
    $script:btnStart.Enabled = $true
    $script:btnStop.Enabled = $false
    $script:btnPause.Enabled = $false
    $script:btnPause.Text = 'Pause'
    $script:cmbIface.Enabled = $true
    Update-StatusBar
}

function Toggle-Pause {
    if (-not $script:Engine.Running) { return }
    $script:Engine.Paused = -not $script:Engine.Paused
    $script:btnPause.Text = if ($script:Engine.Paused) { 'Resume' } else { 'Pause' }
    Write-AppLog $(if ($script:Engine.Paused) { 'Capture paused (incoming frames dropped).' } else { 'Capture resumed.' }) 'INFO'
}

function Clear-Capture {
    if ($script:Engine.Running) {
        $r = [System.Windows.Forms.MessageBox]::Show('Clear the packet list while still capturing?', 'Clear', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
        if ($r -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    }
    $script:AllPackets.Clear()
    $script:ViewPackets.Clear()
    $script:Smb1Hosts.Clear()
    $script:Smb1CommandHist.Clear()
    $script:NextNo = 1
    $script:LastBannerCount = 0
    if ($script:banner) { $script:banner.Visible = $false }
    $script:lvPackets.VirtualListSize = 0
    $script:lvPackets.Invalidate()
    $script:tvDetails.Nodes.Clear()
    $script:hexBox.Clear()
    $script:dgvHosts.Rows.Clear()
    Update-StatusBar
    Write-AppLog 'Packet list cleared.' 'INFO'
}

function Import-DemoCapture {
    $demo = [SmbPacketParser]::BuildDemoPackets()
    [void](Add-PacketsToUi -Packets $demo)
    Refresh-PacketListView
    Update-HostsGrid
    Update-StatsTab
    Update-StatusBar
    Write-AppLog "Loaded $($demo.Length) synthetic demo packets (SMBv1 negotiate, session, tree, create + SMB2 contrast)." 'INFO'
    [void][System.Windows.Forms.MessageBox]::Show(
        "Loaded $($demo.Length) synthetic packets so you can explore the UI without live traffic.`n`nRed rows = SMBv1. Blue rows = SMB2. Click a row, then use Follow Stream / Apply as Filter.",
        'Demo Capture Loaded',
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information)
}

function Open-PcapFile {
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = 'Capture files (*.pcap;*.cap)|*.pcap;*.cap|All files (*.*)|*.*'
    $dlg.Title = 'Open PCAP (Wireshark / this tool)'
    if ($dlg.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
    Import-PcapPath -Path $dlg.FileName
}

function Import-PcapPath {
    param([string]$Path)
    try {
        $script:lblState.Text = 'Loading PCAP...'
        [System.Windows.Forms.Application]::DoEvents()
        $pkts = [SmbPacketParser]::ReadPcap($Path)
        [void](Add-PacketsToUi -Packets $pkts)
        Refresh-PacketListView
        Update-HostsGrid
        Update-StatsTab
        Update-StatusBar
        Write-AppLog "Opened $Path ($($pkts.Length) IPv4/TCP frames parsed)." 'INFO'
    } catch {
        Write-AppLog "PCAP open failed: $($_.Exception.Message)" 'ERROR'
        [void][System.Windows.Forms.MessageBox]::Show("Failed to open PCAP:`n$($_.Exception.Message)", 'Open Failed', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

function Save-PcapFile {
    if ($script:ViewPackets.Count -eq 0) {
        [void][System.Windows.Forms.MessageBox]::Show('No packets in the current view to save.', 'Nothing to Save', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        return
    }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = 'pcap (*.pcap)|*.pcap|CSV summary (*.csv)|*.csv'
    $dlg.FileName = "smbv1-capture-$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    $dlg.Title = 'Save current view'
    if ($dlg.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
    try {
        if ($dlg.FileName -like '*.csv') {
            $script:ViewPackets | Select-Object No, Time, Src, SrcPort, Dst, DstPort, Protocol, Length, SmbVersion, SmbCommand, UserName, SharePath, FileName, Info |
                Export-Csv -Path $dlg.FileName -NoTypeInformation -Encoding UTF8
        } else {
            [SmbPacketParser]::WritePcap($dlg.FileName, $script:ViewPackets.ToArray())
        }
        Write-AppLog "Saved $($script:ViewPackets.Count) packets to $($dlg.FileName)" 'SUCCESS'
        [void][System.Windows.Forms.MessageBox]::Show("Saved $($script:ViewPackets.Count) packets to:`n$($dlg.FileName)`n`nPCAP files open in Wireshark (LINKTYPE_IPV4 / 228).", 'Saved', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    } catch {
        [void][System.Windows.Forms.MessageBox]::Show("Save failed:`n$($_.Exception.Message)", 'Save Failed', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

function Set-DisplayFilter {
    param([string]$Text)
    $script:txtFilter.Text = $Text
    Update-PacketView
}

function Use-FollowStream {
    $p = Get-SelectedPacket
    if (-not $p) { return }
    Set-DisplayFilter -Text ("stream {0}:{1} {2}:{3}" -f $p.Src, $p.SrcPort, $p.Dst, $p.DstPort)
    Write-AppLog "Follow stream $($p.Src):$($p.SrcPort) <-> $($p.Dst):$($p.DstPort)" 'INFO'
}

function Use-FilterSelectedIp {
    $p = Get-SelectedPacket
    if (-not $p) { return }
    $peer = Get-Smb1Peer $p
    Set-DisplayFilter -Text ("ip.addr=={0}" -f $peer.Client)
}

function Toggle-MarkSelected {
    $p = Get-SelectedPacket
    if (-not $p) { return }
    $p.Marked = -not $p.Marked
    $script:lvPackets.Invalidate()
}

function Find-InPackets {
    param([bool]$Forward = $true)
    $q = $script:txtFind.Text
    if ([string]::IsNullOrWhiteSpace($q) -or $script:ViewPackets.Count -eq 0) { return }
    $ql = $q.ToLowerInvariant()
    $start = $script:FindIndex
    if ($script:lvPackets.SelectedIndices.Count -gt 0) { $start = $script:lvPackets.SelectedIndices[0] }
    $n = $script:ViewPackets.Count
    for ($k = 1; $k -le $n; $k++) {
        $idx = if ($Forward) { ($start + $k) % $n } else { ($start - $k + $n) % $n }
        $p = $script:ViewPackets[$idx]
        $hay = ('{0} {1} {2} {3} {4} {5} {6}' -f $p.Src, $p.Dst, $p.Info, $p.UserName, $p.FileName, $p.SharePath, $p.SmbCommand).ToLowerInvariant()
        if ($hay.Contains($ql)) {
            $script:FindIndex = $idx
            $script:lvPackets.SelectedIndices.Clear()
            $script:lvPackets.SelectedIndices.Add($idx)
            $script:lvPackets.EnsureVisible($idx)
            Show-PacketDetails $p
            return
        }
    }
    $script:lblStatusMini.Text = "Find: '$q' not found in current view"
}

function Update-HostsGrid {
    if (-not $script:dgvHosts) { return }
    $sel = $null
    if ($script:dgvHosts.SelectedRows.Count -gt 0) { $sel = $script:dgvHosts.SelectedRows[0].Cells['IP'].Value }
    $script:dgvHosts.Rows.Clear()
    foreach ($ip in ($script:Smb1Hosts.Keys | Sort-Object)) {
        $h = $script:Smb1Hosts[$ip]
        $cmds = ($h.Commands.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 4 | ForEach-Object { '{0}({1})' -f $_.Key, $_.Value }) -join ', '
        $users = ($h.Users -join '; ')
        $shares = ($h.Shares -join '; ')
        $idx = $script:dgvHosts.Rows.Add($h.IP, $h.HostName, $h.Role, $h.Packets, $h.FirstSeen.ToString('HH:mm:ss'), $h.LastSeen.ToString('HH:mm:ss'), $users, $shares, $cmds, $h.Sample)
        $script:dgvHosts.Rows[$idx].DefaultCellStyle.BackColor = $script:C.Smb1
        if ($sel -and $h.IP -eq $sel) { $script:dgvHosts.Rows[$idx].Selected = $true }
    }
}

function Resolve-HostNames {
    foreach ($ip in @($script:Smb1Hosts.Keys)) {
        try {
            $entry = [System.Net.Dns]::GetHostEntry($ip)
            $script:Smb1Hosts[$ip].HostName = $entry.HostName
        } catch {
            $script:Smb1Hosts[$ip].HostName = '(no PTR)'
        }
        [System.Windows.Forms.Application]::DoEvents()
    }
    Update-HostsGrid
    Write-AppLog 'Reverse DNS lookup complete for SMBv1 hosts.' 'INFO'
}

function Export-HostsCsv {
    if ($script:Smb1Hosts.Count -eq 0) {
        [void][System.Windows.Forms.MessageBox]::Show('No SMBv1 hosts recorded yet.', 'Empty', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        return
    }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = 'CSV (*.csv)|*.csv'
    $dlg.FileName = "smbv1-hosts-$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($dlg.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
    $rows = foreach ($ip in ($script:Smb1Hosts.Keys | Sort-Object)) {
        $h = $script:Smb1Hosts[$ip]
        [pscustomobject]@{
            IP = $h.IP; HostName = $h.HostName; Role = $h.Role; Packets = $h.Packets
            FirstSeen = $h.FirstSeen; LastSeen = $h.LastSeen
            Users = ($h.Users -join '; '); Shares = ($h.Shares -join '; ')
            Files = ($h.Files -join '; '); Commands = (($h.Commands.GetEnumerator() | ForEach-Object { '{0}={1}' -f $_.Key, $_.Value }) -join '; ')
        }
    }
    $rows | Export-Csv -Path $dlg.FileName -NoTypeInformation -Encoding UTF8
    Write-AppLog "Exported SMBv1 hosts to $($dlg.FileName)" 'SUCCESS'
}

function Update-StatsTab {
    if (-not $script:txtStats) { return }
    $stats = $script:Engine.GetStats()
    $total = [Math]::Max(1, $script:AllPackets.Count)
    $c1 = @($script:AllPackets | Where-Object { $_.IsSmb1 }).Count
    $c2 = @($script:AllPackets | Where-Object { $_.IsSmb2 -or $_.Protocol -eq 'SMB2' }).Count
    $c3 = @($script:AllPackets | Where-Object { $_.IsSmb3 -or $_.Protocol -eq 'SMB3' }).Count
    $tcp = @($script:AllPackets | Where-Object { $_.Protocol -eq 'TCP' }).Count
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("SMBv1 Traffic Analyzer v$($script:AppVersion)  -  Statistics")
    [void]$sb.AppendLine(('=' * 64))
    [void]$sb.AppendLine("Engine captured : $($stats.Captured)")
    [void]$sb.AppendLine("Buffered frames : $($script:AllPackets.Count)")
    [void]$sb.AppendLine("Displayed       : $($script:ViewPackets.Count)")
    [void]$sb.AppendLine("Dropped         : $($stats.Dropped)")
    [void]$sb.AppendLine("Bytes (engine)  : $($stats.Bytes)")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("Protocol hierarchy")
    [void]$sb.AppendLine(("  SMBv1  {0,8}  {1,6:N1}%" -f $c1, (100.0 * $c1 / $total)))
    [void]$sb.AppendLine(("  SMB2   {0,8}  {1,6:N1}%" -f $c2, (100.0 * $c2 / $total)))
    [void]$sb.AppendLine(("  SMB3   {0,8}  {1,6:N1}%" -f $c3, (100.0 * $c3 / $total)))
    [void]$sb.AppendLine(("  TCP    {0,8}  {1,6:N1}%" -f $tcp, (100.0 * $tcp / $total)))
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("SMBv1 hosts     : $($script:Smb1Hosts.Count)")
    [void]$sb.AppendLine("SMBv1 commands")
    foreach ($e in ($script:Smb1CommandHist.GetEnumerator() | Sort-Object Value -Descending)) {
        [void]$sb.AppendLine(("  {0,-24} {1}" -f $e.Key, $e.Value))
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("Top SMBv1 talkers")
    $top = $script:Smb1Hosts.Values | Sort-Object Packets -Descending | Select-Object -First 12
    foreach ($h in $top) {
        [void]$sb.AppendLine(("  {0,-16} {1,-8} {2,6} pkts  {3}" -f $h.IP, $h.Role, $h.Packets, $h.HostName))
    }
    $script:txtStats.Text = $sb.ToString()
}

function Get-SmbServerConfigText {
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("Computer : $env:COMPUTERNAME")
    [void]$sb.AppendLine("User     : $env:USERDOMAIN\$env:USERNAME")
    [void]$sb.AppendLine("Elevated : $($script:IsAdmin)")
    [void]$sb.AppendLine("Time     : $(Get-Timestamp)")
    [void]$sb.AppendLine(('=' * 64))
    try {
        $os = Get-WmiObject Win32_OperatingSystem
        [void]$sb.AppendLine("OS       : $($os.Caption)  (Build $($os.BuildNumber))")
        [void]$sb.AppendLine("Version  : $($os.Version)")
    } catch {
        [void]$sb.AppendLine("OS       : (WMI query failed)")
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("Registry  HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters")
    $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    foreach ($n in @('SMB1', 'SMB2', 'EnableSMB1Protocol', 'EnableOplocks', 'AutoShareWks', 'AutoShareServer')) {
        try {
            $v = Get-ItemProperty -Path $p -Name $n -ErrorAction Stop | Select-Object -ExpandProperty $n
            [void]$sb.AppendLine(("  {0,-22} {1}" -f $n, $v))
        } catch {
            [void]$sb.AppendLine(("  {0,-22} (not set)" -f $n))
        }
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("Services")
    foreach ($svc in @('LanmanServer', 'LanmanWorkstation', 'mrxsmb10', 'mrxsmb20')) {
        try {
            $s = Get-WmiObject Win32_Service -Filter "Name='$svc'"
            if ($s) { [void]$sb.AppendLine(("  {0,-22} State={1}  Start={2}" -f $svc, $s.State, $s.StartMode)) }
            else { [void]$sb.AppendLine(("  {0,-22} (not installed)" -f $svc)) }
        } catch {
            [void]$sb.AppendLine(("  {0,-22} (query failed)" -f $svc))
        }
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("Get-SmbServerConfiguration (2012+ / SmbShare module)")
    try {
        Import-Module SmbShare -ErrorAction Stop
        $cfg = Get-SmbServerConfiguration -ErrorAction Stop
        foreach ($n in @('EnableSMB1Protocol', 'EnableSMB2Protocol', 'AuditSmb1Access', 'EncryptData', 'RejectUnencryptedAccess', 'AnnounceServer')) {
            if ($cfg.PSObject.Properties.Name -contains $n) {
                [void]$sb.AppendLine(("  {0,-28} {1}" -f $n, $cfg.$n))
            }
        }
    } catch {
        [void]$sb.AppendLine("  SmbShare module / cmdlet not available: $($_.Exception.Message)")
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("Current inbound SMB sessions (Win32_ServerConnection)")
    try {
        $conns = @(Get-WmiObject Win32_ServerConnection -ErrorAction Stop)
        [void]$sb.AppendLine("  Count: $($conns.Count)")
        foreach ($c in $conns | Select-Object -First 40) {
            [void]$sb.AppendLine(("  User={0,-20} Computer={1,-18} Share={2}" -f $c.UserName, $c.ComputerName, $c.ShareName))
        }
    } catch {
        [void]$sb.AppendLine("  $($_.Exception.Message)")
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("Notes for Server 2012 R2 and older:")
    [void]$sb.AppendLine("  - SMBv1 is installed and enabled by default.")
    [void]$sb.AppendLine("  - Set-SmbServerConfiguration -EnableSMB1Protocol `$false disables the SERVER dialect.")
    [void]$sb.AppendLine("  - Client-side SMBv1 is the mrxsmb10 driver (Start=Disabled after depend= update).")
    [void]$sb.AppendLine("  - A reboot is required for a clean disable.")
    [void]$sb.AppendLine("  - Capture still sees SMBv1 if a remote client speaks it before you disable it.")
    return $sb.ToString()
}

function Refresh-ConfigTab {
    $script:txtConfig.Text = Get-SmbServerConfigText
    Write-AppLog 'Refreshed local SMB server configuration.' 'INFO'
}

function Disable-Smb1OnThisServer {
    if (-not $script:IsAdmin) {
        [void][System.Windows.Forms.MessageBox]::Show('Disabling SMBv1 requires Administrator.', 'Denied', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Stop)
        return
    }
    $c1 = [System.Windows.Forms.MessageBox]::Show(
        "This will DISABLE the SMBv1 SERVER dialect on $env:COMPUTERNAME.`n`nClients that only speak SMBv1 will lose access to file shares.`nA reboot is required for a complete take-down.`n`nContinue?",
        'Confirm SMBv1 Disable - 1 of 2',
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($c1 -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    $c2 = [System.Windows.Forms.MessageBox]::Show(
        'FINAL CONFIRMATION: disable SMBv1 on this server now?',
        'Confirm SMBv1 Disable - 2 of 2',
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Stop)
    if ($c2 -ne [System.Windows.Forms.DialogResult]::Yes) { return }

    $log = New-Object System.Text.StringBuilder
    try {
        Import-Module SmbShare -ErrorAction Stop
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
        [void]$log.AppendLine('Set-SmbServerConfiguration -EnableSMB1Protocol $false  OK')
    } catch {
        [void]$log.AppendLine("Set-SmbServerConfiguration failed: $($_.Exception.Message)")
    }
    try {
        $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        New-ItemProperty -Path $path -Name 'SMB1' -Value 0 -PropertyType DWord -Force | Out-Null
        [void]$log.AppendLine('Registry LanmanServer\Parameters\SMB1 = 0  OK')
    } catch {
        [void]$log.AppendLine("Registry SMB1=0 failed: $($_.Exception.Message)")
    }
    Write-AppLog $log.ToString() 'WARN'
    Refresh-ConfigTab
    [void][System.Windows.Forms.MessageBox]::Show(
        "SMBv1 disable attempted.`n`n$($log.ToString())`nReboot this server, then recapture to confirm no SMBv1 remains.",
        'SMBv1 Disable',
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information)
}

function Scan-SmbEventLogs {
    $script:dgvEvents.Rows.Clear()
    $hours = [int]$script:numHours.Value
    $since = (Get-Date).AddHours(-$hours)
    Write-AppLog "Scanning SMB-related event logs since $since ..." 'INFO'
    $logs = @(
        'System',
        'Microsoft-Windows-SMBServer/Operational',
        'Microsoft-Windows-SMBServer/Security',
        'Microsoft-Windows-SMBServer/Audit',
        'Microsoft-Windows-SmbClient/Operational',
        'Microsoft-Windows-SmbClient/Connectivity',
        'Microsoft-Windows-SmbClient/Security'
    )
    $count = 0
    foreach ($log in $logs) {
        try {
            $events = Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $since } -ErrorAction Stop -MaxEvents 400
            foreach ($e in $events) {
                $msg = ''
                try { $msg = $e.Message } catch { $msg = '' }
                if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 300) }
                $looksSmb1 = ($msg -match 'SMB1|SMB 1|NT LM 0\.12|mrxsmb10|EnableSMB1')
                $idx = $script:dgvEvents.Rows.Add($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'), $log, $e.Id, $e.LevelDisplayName, $msg)
                if ($looksSmb1) {
                    $script:dgvEvents.Rows[$idx].DefaultCellStyle.BackColor = $script:C.Smb1
                }
                $count++
            }
        } catch {
            Write-AppLog "Log '$log' skipped: $($_.Exception.Message)" 'WARN'
        }
        [System.Windows.Forms.Application]::DoEvents()
    }
    Write-AppLog "Event scan complete. $count event(s) listed. Red rows mention SMBv1." 'INFO'
}

function Copy-SelectedSummary {
    $p = Get-SelectedPacket
    if (-not $p) { return }
    $text = "No={0} Time={1} {2}:{3} -> {4}:{5} {6} len={7} {8}" -f $p.No, $p.Time.ToString('o'), $p.Src, $p.SrcPort, $p.Dst, $p.DstPort, $p.Protocol, $p.Length, $p.Info
    [System.Windows.Forms.Clipboard]::SetText($text)
}

function Sort-PacketView {
    param([int]$Column)
    if ($script:SortColumn -eq $Column) { $script:SortAscending = -not $script:SortAscending } else { $script:SortAscending = $true }
    $script:SortColumn = $Column
    $props = @('No', 'Time', 'Src', 'SrcPort', 'Dst', 'DstPort', 'Protocol', 'Length', 'Info')
    $name = $props[$Column]
    $arr = $script:ViewPackets.ToArray()
    if ($script:SortAscending) {
        $arr = $arr | Sort-Object -Property $name
    } else {
        $arr = $arr | Sort-Object -Property $name -Descending
    }
    $script:ViewPackets.Clear()
    if ($arr) { $script:ViewPackets.AddRange([SmbPacket[]]@($arr)) }
    $script:lvPackets.Invalidate()
}

function Show-GotoPacket {
    $inputBox = New-Object System.Windows.Forms.Form
    $inputBox.Text = 'Go To Packet'
    $inputBox.Size = New-Object System.Drawing.Size(320, 140)
    $inputBox.StartPosition = 'CenterParent'
    $inputBox.FormBorderStyle = 'FixedDialog'
    $inputBox.MaximizeBox = $false
    $inputBox.MinimizeBox = $false
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = 'Packet number:'
    $lbl.Location = New-Object System.Drawing.Point(15, 15)
    $lbl.AutoSize = $true
    $tb = New-Object System.Windows.Forms.TextBox
    $tb.Location = New-Object System.Drawing.Point(15, 40)
    $tb.Width = 270
    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = 'Go'
    $ok.Location = New-Object System.Drawing.Point(130, 70)
    $ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $inputBox.Controls.AddRange(@($lbl, $tb, $ok))
        $inputBox.AcceptButton = $ok
    if ($inputBox.ShowDialog($script:MainForm) -eq [System.Windows.Forms.DialogResult]::OK) {
        $n = 0
        if ([int]::TryParse($tb.Text, [ref]$n)) {
            for ($i = 0; $i -lt $script:ViewPackets.Count; $i++) {
                if ($script:ViewPackets[$i].No -eq $n) {
                    $script:lvPackets.SelectedIndices.Clear()
                    $script:lvPackets.SelectedIndices.Add($i)
                    $script:lvPackets.EnsureVisible($i)
                    Show-PacketDetails $script:ViewPackets[$i]
                    return
                }
            }
        }
    }
}

function Get-HelpText {
    return @"
SMBv1 TRAFFIC ANALYZER v$($script:AppVersion)
Wireshark-style capture for Windows Server 2012 R2 / 2008 R2 (Windows PowerShell 5.1)

WHY THIS EXISTS
  SMBv1 (NT LM 0.12) is obsolete. WannaCry/EternalBlue, credential relay, and
  unsigned-session attacks all depend on it. Server 2012 R2 still ships with
  SMBv1 enabled. This tool shows you WHO is still speaking it on the wire.

HOW TO RUN
  1. Copy SMBv1-TrafficAnalyzer.ps1 to the server.
  2. Right-click powershell.exe -> Run as administrator.
  3. powershell.exe -ExecutionPolicy Bypass -STA -File .\SMBv1-TrafficAnalyzer.ps1
  4. Pick the IPv4 address of the interface that faces clients.
  5. Click Start. SMBv1 rows turn red. Hosts tab lists talkers.

NO LIVE TRAFFIC?
  File > Load demo capture injects synthetic SMBv1 + SMB2 frames so you can
  learn the UI. File > Open PCAP loads a Wireshark capture (Ethernet or raw IPv4).
  Saved files from this tool open in Wireshark (LINKTYPE 228 / IPv4).

WHAT "LIKE WIRESHARK" MEANS HERE
  - Three panes: packet list, protocol tree, hex dump (SMB magic highlighted)
  - Display filter box with AND / OR / NOT
  - Follow TCP stream, mark packets (Space), go to packet (Ctrl+G)
  - Color by protocol (SMBv1 red, SMB2 blue, SMB3 green)
  - Right-click: filter this IP, copy summary, follow stream
  - Export current view as PCAP or CSV

DISPLAY FILTERS
  smb1
  smb1 and negotiate
  smb2 or smb3
  not tcp
  ip.addr==10.10.50.88
  ip.src==10.10.50.88
  tcp.port==445
  tcp.port==139
  smb.cmd==0x72
  user:legacyapp
  file:data.mdb
  contains:NT LM
  marked
  stream 10.10.50.88:55123 10.10.50.10:445

KEYBOARD
  Ctrl+E   Start / Stop capture
  Ctrl+L   Focus display filter
  Ctrl+F   Find
  Ctrl+G   Go to packet number
  Ctrl+S   Save current view
  Ctrl+O   Open PCAP
  Space    Mark / unmark selected packet
  Enter    Apply filter

HOW DETECTION WORKS
  Port 445 (direct TCP) and 139 (NetBIOS session) payloads are searched for:
    FF 53 4D 42   = SMBv1     ("NT LM 0.12" and older dialects)
    FE 53 4D 42   = SMB 2.x / 3.x
    FD 53 4D 42   = SMB 3 transform (encrypted)
  Negotiate requests list dialects. Session Setup is scanned for NTLMSSP Type 3
  (username / domain / workstation). Tree Connect and NT Create extract paths.

LIMITATIONS vs REAL WIRESHARK
  - IPv4 only (raw sockets on 2012 R2). No Ethernet header on live frames.
  - Captures traffic to/from THIS host, not a SPAN/mirror port.
  - No full TCP reassembly; a mid-segment SMB PDU may be missed.
  - Requires Administrator for live capture.
  - Does not exploit, scan, or authenticate to remote hosts.

HARDENING (2012 R2)
  Set-SmbServerConfiguration -EnableSMB1Protocol `$false
  Registry: HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1 = 0
  Then reboot. Use this analyzer afterwards to prove SMBv1 is gone.
"@
}

# ============================================================
# BUILD GUI
# ============================================================
$script:Tip = New-Object System.Windows.Forms.ToolTip
$script:Tip.AutoPopDelay = 14000
$script:Tip.InitialDelay = 350

$form = New-Object System.Windows.Forms.Form
$form.Text = "SMBv1 Traffic Analyzer v$($script:AppVersion) - Wireshark-style capture"
$form.Size = New-Object System.Drawing.Size(1440, 920)
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$form.BackColor = $script:C.Bg
$form.MinimumSize = New-Object System.Drawing.Size(1100, 720)
$form.KeyPreview = $true
$form.Icon = [System.Drawing.SystemIcons]::Shield
Enable-DoubleBuffer $form
$script:MainForm = $form

# --- Header ---
$header = New-Object System.Windows.Forms.Panel
$header.Dock = 'Top'
$header.Height = 58
$header.BackColor = $script:C.Header

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = 'SMBv1 Traffic Analyzer'
$lblTitle.Font = New-Object System.Drawing.Font('Segoe UI', 16, [System.Drawing.FontStyle]::Bold)
$lblTitle.ForeColor = $script:C.White
$lblTitle.AutoSize = $true
$lblTitle.Location = New-Object System.Drawing.Point(16, 8)

$lblSub = New-Object System.Windows.Forms.Label
$lblSub.Text = 'PowerShell 5.1  |  Windows Server 2012 R2 and older  |  Live capture + PCAP  |  No Npcap required'
$lblSub.Font = New-Object System.Drawing.Font('Segoe UI', 8.5)
$lblSub.ForeColor = [System.Drawing.Color]::FromArgb(160, 185, 215)
$lblSub.AutoSize = $true
$lblSub.Location = New-Object System.Drawing.Point(18, 36)

$lblVer = New-Object System.Windows.Forms.Label
$lblVer.Text = "v$($script:AppVersion)"
$lblVer.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$lblVer.ForeColor = [System.Drawing.Color]::FromArgb(160, 185, 215)
$lblVer.AutoSize = $true
$lblVer.Anchor = 'Top, Right'
$lblVer.Location = New-Object System.Drawing.Point(1360, 20)
$header.Controls.AddRange(@($lblTitle, $lblSub, $lblVer))

# --- Toolbar ---
$tool = New-Object System.Windows.Forms.Panel
$tool.Dock = 'Top'
$tool.Height = 46
$tool.BackColor = $script:C.Header2
$tool.Padding = New-Object System.Windows.Forms.Padding(10, 8, 10, 8)

$lblIf = New-Object System.Windows.Forms.Label
$lblIf.Text = 'Interface'
$lblIf.ForeColor = $script:C.White
$lblIf.AutoSize = $true
$lblIf.Location = New-Object System.Drawing.Point(12, 14)

$script:cmbIface = New-Object System.Windows.Forms.ComboBox
$script:cmbIface.DropDownStyle = 'DropDownList'
$script:cmbIface.Width = 300
$script:cmbIface.Location = New-Object System.Drawing.Point(78, 10)
$script:cmbIface.DisplayMember = 'Display'
$script:cmbIface.ValueMember = 'IP'
$script:cmbIface.BackColor = [System.Drawing.Color]::FromArgb(18, 18, 22)
$script:cmbIface.ForeColor = $script:C.OkGreen
$script:cmbIface.FlatStyle = 'Flat'

$ifaces = @(Get-CaptureInterfaces)
foreach ($it in $ifaces) { [void]$script:cmbIface.Items.Add($it) }
if ($InterfaceIP) {
    for ($i = 0; $i -lt $script:cmbIface.Items.Count; $i++) {
        if ($script:cmbIface.Items[$i].IP -eq $InterfaceIP) { $script:cmbIface.SelectedIndex = $i; break }
    }
}
if ($script:cmbIface.SelectedIndex -lt 0 -and $script:cmbIface.Items.Count -gt 0) { $script:cmbIface.SelectedIndex = 0 }

$script:btnStart = New-FlatButton -Text 'Start' -Width 78 -BackColor $script:C.Green -TipText 'Start live capture (Admin). Ctrl+E' -OnClick { Start-Capture }
$script:btnStop  = New-FlatButton -Text 'Stop'  -Width 78 -BackColor $script:C.Red   -TipText 'Stop live capture' -OnClick { Stop-Capture }
$script:btnPause = New-FlatButton -Text 'Pause' -Width 78 -BackColor $script:C.Orange -TipText 'Pause/resume (drops frames while paused)' -OnClick { Toggle-Pause }
$script:btnStop.Enabled = $false
$script:btnPause.Enabled = $false
$script:btnStart.Location = New-Object System.Drawing.Point(390, 8)
$script:btnStop.Location  = New-Object System.Drawing.Point(474, 8)
$script:btnPause.Location = New-Object System.Drawing.Point(558, 8)

$script:chkPortsOnly = New-Object System.Windows.Forms.CheckBox
$script:chkPortsOnly.Text = 'SMB ports (139/445)'
$script:chkPortsOnly.ForeColor = $script:C.White
$script:chkPortsOnly.AutoSize = $true
$script:chkPortsOnly.Checked = $true
$script:chkPortsOnly.Location = New-Object System.Drawing.Point(650, 12)
$script:Tip.SetToolTip($script:chkPortsOnly, 'Capture filter: only TCP 139 and 445. Uncheck to capture all IPv4 (heavier).')
$script:chkPortsOnly.Add_CheckedChanged({ if ($script:Engine) { $script:Engine.SmbPortsOnly = $script:chkPortsOnly.Checked } })

$script:chkSmbPayload = New-Object System.Windows.Forms.CheckBox
$script:chkSmbPayload.Text = 'SMB PDUs only'
$script:chkSmbPayload.ForeColor = $script:C.White
$script:chkSmbPayload.AutoSize = $true
$script:chkSmbPayload.Location = New-Object System.Drawing.Point(810, 12)
$script:Tip.SetToolTip($script:chkSmbPayload, 'Capture filter: drop TCP control segments without an SMB header.')
$script:chkSmbPayload.Add_CheckedChanged({ if ($script:Engine) { $script:Engine.SmbPayloadOnly = $script:chkSmbPayload.Checked } })

$script:chkAutoScroll = New-Object System.Windows.Forms.CheckBox
$script:chkAutoScroll.Text = 'Auto-scroll'
$script:chkAutoScroll.ForeColor = $script:C.White
$script:chkAutoScroll.AutoSize = $true
$script:chkAutoScroll.Checked = $true
$script:chkAutoScroll.Location = New-Object System.Drawing.Point(940, 12)

$btnClear = New-FlatButton -Text 'Clear' -Width 70 -BackColor $script:C.Gray -Bold $false -OnClick { Clear-Capture } -TipText 'Clear packet list'
$btnClear.Location = New-Object System.Drawing.Point(1040, 8)
$btnDemo = New-FlatButton -Text 'Demo' -Width 70 -BackColor $script:C.Teal -Bold $false -OnClick { Import-DemoCapture } -TipText 'Load synthetic SMBv1/SMB2 packets'
$btnDemo.Location = New-Object System.Drawing.Point(1116, 8)
$btnOpen = New-FlatButton -Text 'Open' -Width 70 -BackColor $script:C.Blue -Bold $false -OnClick { Open-PcapFile } -TipText 'Open a .pcap (Ctrl+O)'
$btnOpen.Location = New-Object System.Drawing.Point(1192, 8)
$btnSave = New-FlatButton -Text 'Save' -Width 70 -BackColor $script:C.Dark -Bold $false -OnClick { Save-PcapFile } -TipText 'Save current view as pcap/csv (Ctrl+S)'
$btnSave.Location = New-Object System.Drawing.Point(1268, 8)

$tool.Controls.AddRange(@($lblIf, $script:cmbIface, $script:btnStart, $script:btnStop, $script:btnPause, $script:chkPortsOnly, $script:chkSmbPayload, $script:chkAutoScroll, $btnClear, $btnDemo, $btnOpen, $btnSave))

# --- Filter bar ---
$filterBar = New-Object System.Windows.Forms.Panel
$filterBar.Dock = 'Top'
$filterBar.Height = 40
$filterBar.BackColor = [System.Drawing.Color]::FromArgb(236, 239, 244)

$lblF = New-Object System.Windows.Forms.Label
$lblF.Text = 'Display filter'
$lblF.AutoSize = $true
$lblF.Location = New-Object System.Drawing.Point(12, 11)
$lblF.ForeColor = $script:C.Text

$script:cmbPreset = New-Object System.Windows.Forms.ComboBox
$script:cmbPreset.DropDownStyle = 'DropDownList'
$script:cmbPreset.Width = 160
$script:cmbPreset.Location = New-Object System.Drawing.Point(100, 8)
[void]$script:cmbPreset.Items.AddRange(@(
    '(no preset)',
    'smb1',
    'smb1 and negotiate',
    'smb1 and session',
    'smb1 and tree',
    'smb1 and create',
    'smb2 or smb3',
    'tcp.port==445',
    'tcp.port==139',
    'marked'
))
$script:cmbPreset.SelectedIndex = 0
$script:cmbPreset.Add_SelectedIndexChanged({
    $v = $script:cmbPreset.SelectedItem.ToString()
    if ($v -ne '(no preset)') { Set-DisplayFilter -Text $v }
})

$script:txtFilter = New-Object System.Windows.Forms.TextBox
$script:txtFilter.Font = New-Object System.Drawing.Font('Consolas', 10)
$script:txtFilter.Location = New-Object System.Drawing.Point(268, 8)
$script:txtFilter.Width = 520
$script:txtFilter.Anchor = 'Top, Left, Right'
$script:Tip.SetToolTip($script:txtFilter, "Examples: smb1   smb1 and ip.addr==10.1.1.8   user:bob   not smb2   Enter to apply")
$script:txtFilter.Add_KeyDown({
    param($s, $e)
    if ($e.KeyCode -eq 'Enter') { $e.SuppressKeyPress = $true; Update-PacketView }
})

$script:btnApply = New-FlatButton -Text 'Apply' -Width 70 -Height 26 -BackColor $script:C.Blue -OnClick { Update-PacketView }
$script:btnApply.Anchor = 'Top, Right'
$script:btnReset = New-FlatButton -Text 'Reset' -Width 70 -Height 26 -BackColor $script:C.Gray -Bold $false -OnClick {
    $script:cmbPreset.SelectedIndex = 0
    $script:chkSmb1Only.Checked = $false
    Set-DisplayFilter -Text ''
}
$script:btnReset.Anchor = 'Top, Right'

$script:chkSmb1Only = New-Object System.Windows.Forms.CheckBox
$script:chkSmb1Only.Text = 'SMBv1 only'
$script:chkSmb1Only.AutoSize = $true
$script:chkSmb1Only.Anchor = 'Top, Right'
$script:chkSmb1Only.Location = New-Object System.Drawing.Point(952, 10)
$script:chkSmb1Only.ForeColor = $script:C.Red
$script:chkSmb1Only.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$script:chkSmb1Only.Add_CheckedChanged({ Update-PacketView })

$script:lblFind = New-Object System.Windows.Forms.Label
$script:lblFind.Text = 'Find'
$script:lblFind.AutoSize = $true
$script:lblFind.Anchor = 'Top, Right'
$script:lblFind.Location = New-Object System.Drawing.Point(1070, 11)

$script:txtFind = New-Object System.Windows.Forms.TextBox
$script:txtFind.Location = New-Object System.Drawing.Point(1104, 8)
$script:txtFind.Width = 150
$script:txtFind.Anchor = 'Top, Right'
$script:txtFind.Add_KeyDown({
    param($s, $e)
    if ($e.KeyCode -eq 'Enter') { $e.SuppressKeyPress = $true; Find-InPackets -Forward $true }
})
$script:btnNext = New-FlatButton -Text '>' -Width 28 -Height 26 -BackColor $script:C.Dark -Bold $false -OnClick { Find-InPackets -Forward $true }
$script:btnNext.Location = New-Object System.Drawing.Point(1260, 7)
$script:btnPrev = New-FlatButton -Text '<' -Width 28 -Height 26 -BackColor $script:C.Dark -Bold $false -OnClick { Find-InPackets -Forward $false }
$script:btnPrev.Location = New-Object System.Drawing.Point(1292, 7)
$script:btnNext.Anchor = 'Top, Right'
$script:btnPrev.Anchor = 'Top, Right'

$filterBar.Controls.AddRange(@($lblF, $script:cmbPreset, $script:txtFilter, $script:btnApply, $script:btnReset, $script:chkSmb1Only, $script:lblFind, $script:txtFind, $script:btnPrev, $script:btnNext))

function Update-FilterBarLayout {
    $w = $filterBar.ClientSize.Width
    if ($w -lt 900) { return }
    $script:btnPrev.Left  = $w - 40
    $script:btnNext.Left  = $w - 72
    $script:txtFind.Left  = $w - 230
    $script:lblFind.Left  = $w - 264
    $script:chkSmb1Only.Left = $w - 370
    $script:btnReset.Left = $w - 450
    $script:btnApply.Left = $w - 526
    $script:txtFilter.Width = [Math]::Max(160, $script:btnApply.Left - $script:txtFilter.Left - 8)
}

# --- Alert banner ---
$script:banner = New-Object System.Windows.Forms.Label
$script:banner.Dock = 'Top'
$script:banner.Height = 28
$script:banner.BackColor = $script:C.AlertBg
$script:banner.ForeColor = $script:C.White
$script:banner.Font = New-Object System.Drawing.Font('Segoe UI', 9.5, [System.Drawing.FontStyle]::Bold)
$script:banner.TextAlign = 'MiddleLeft'
$script:banner.Visible = $false

# --- Admin hint ---
$script:adminHint = New-Object System.Windows.Forms.Label
$script:adminHint.Dock = 'Top'
$script:adminHint.Height = 24
$script:adminHint.BackColor = [System.Drawing.Color]::FromArgb(202, 131, 0)
$script:adminHint.ForeColor = $script:C.White
$script:adminHint.TextAlign = 'MiddleLeft'
$script:adminHint.Text = '  Not running as Administrator - live capture is disabled. Open a PCAP, load Demo, or relaunch elevated.'
$script:adminHint.Visible = -not $script:IsAdmin

# --- Tabs ---
$script:tabMain = New-Object System.Windows.Forms.TabControl
$script:tabMain.Dock = 'Fill'
$script:tabMain.Font = New-Object System.Drawing.Font('Segoe UI', 9.5, [System.Drawing.FontStyle]::Bold)
$script:tabMain.Padding = New-Object System.Drawing.Point(10, 5)

$script:tabCapture = New-Object System.Windows.Forms.TabPage
$script:tabCapture.Text = '  Live Capture  '
$script:tabCapture.BackColor = $script:C.Bg

$script:tabHosts = New-Object System.Windows.Forms.TabPage
$script:tabHosts.Text = '  SMBv1 Hosts  '
$script:tabHosts.BackColor = $script:C.Bg

$script:tabStats = New-Object System.Windows.Forms.TabPage
$script:tabStats.Text = '  Statistics  '
$script:tabStats.BackColor = $script:C.Bg

$script:tabConfig = New-Object System.Windows.Forms.TabPage
$script:tabConfig.Text = '  Server Config  '
$script:tabConfig.BackColor = $script:C.Bg

$script:tabEvents = New-Object System.Windows.Forms.TabPage
$script:tabEvents.Text = '  Event Log  '
$script:tabEvents.BackColor = $script:C.Bg

$script:tabHelp = New-Object System.Windows.Forms.TabPage
$script:tabHelp.Text = '  Help  '
$script:tabHelp.BackColor = $script:C.Bg

$script:tabLog = New-Object System.Windows.Forms.TabPage
$script:tabLog.Text = '  Log  '
$script:tabLog.BackColor = $script:C.Bg

[void]$script:tabMain.TabPages.AddRange(@($script:tabCapture, $script:tabHosts, $script:tabStats, $script:tabConfig, $script:tabEvents, $script:tabHelp, $script:tabLog))

# --- Capture tab: 3-pane Wireshark layout ---
$splitH = New-Object System.Windows.Forms.SplitContainer
$splitH.Dock = 'Fill'
$splitH.Orientation = 'Horizontal'
$splitH.SplitterWidth = 6
$splitH.BackColor = $script:C.Split
$splitH.Panel1.BackColor = $script:C.Bg
$splitH.Panel2.BackColor = $script:C.Bg

$script:lvPackets = New-Object System.Windows.Forms.ListView
$script:lvPackets.Dock = 'Fill'
$script:lvPackets.View = 'Details'
$script:lvPackets.FullRowSelect = $true
$script:lvPackets.GridLines = $true
$script:lvPackets.HideSelection = $false
$script:lvPackets.VirtualMode = $true
$script:lvPackets.VirtualListSize = 0
$script:lvPackets.Font = New-Object System.Drawing.Font('Consolas', 9)
$script:lvPackets.BackColor = $script:C.White
Enable-DoubleBuffer $script:lvPackets
[void]$script:lvPackets.Columns.Add('No', 60)
[void]$script:lvPackets.Columns.Add('Time', 110)
[void]$script:lvPackets.Columns.Add('Source', 120)
[void]$script:lvPackets.Columns.Add('Src Port', 70)
[void]$script:lvPackets.Columns.Add('Destination', 120)
[void]$script:lvPackets.Columns.Add('Dst Port', 70)
[void]$script:lvPackets.Columns.Add('Protocol', 70)
[void]$script:lvPackets.Columns.Add('Length', 70)
[void]$script:lvPackets.Columns.Add('Info', 620)

$script:lvPackets.Add_RetrieveVirtualItem({
    param($s, $e)
    try {
        $idx = $e.ItemIndex
        if ($idx -lt 0 -or $idx -ge $script:ViewPackets.Count) {
            $e.Item = New-Object System.Windows.Forms.ListViewItem('')
            return
        }
        $p = $script:ViewPackets[$idx]
        $item = New-Object System.Windows.Forms.ListViewItem($p.No.ToString())
        [void]$item.SubItems.Add($p.Time.ToString('HH:mm:ss.fff'))
        [void]$item.SubItems.Add($p.Src)
        [void]$item.SubItems.Add($p.SrcPort.ToString())
        [void]$item.SubItems.Add($p.Dst)
        [void]$item.SubItems.Add($p.DstPort.ToString())
        [void]$item.SubItems.Add($p.Protocol)
        [void]$item.SubItems.Add($p.Length.ToString())
        [void]$item.SubItems.Add($p.Info)
        $item.BackColor = Get-PacketRowColor $p
        if ($p.IsSmb1) { $item.ForeColor = [System.Drawing.Color]::FromArgb(90, 0, 0) }
        $e.Item = $item
    } catch {
        $e.Item = New-Object System.Windows.Forms.ListViewItem('')
    }
})
$script:lvPackets.Add_SelectedIndexChanged({
    $p = Get-SelectedPacket
    if ($p) { Show-PacketDetails $p }
})
$script:lvPackets.Add_ColumnClick({ param($s, $e) Sort-PacketView -Column $e.Column })
$script:lvPackets.Add_DoubleClick({ Use-FollowStream })
$script:lvPackets.Add_KeyDown({
    param($s, $e)
    if ($e.KeyCode -eq 'Space') { $e.SuppressKeyPress = $true; Toggle-MarkSelected }
})

$ctx = New-Object System.Windows.Forms.ContextMenuStrip
$mFollow = $ctx.Items.Add('Follow TCP stream')
$mFollow.add_Click({ Use-FollowStream })
$mIp = $ctx.Items.Add('Display filter: this client IP')
$mIp.add_Click({ Use-FilterSelectedIp })
$mSmb1 = $ctx.Items.Add('Display filter: smb1')
$mSmb1.add_Click({ Set-DisplayFilter -Text 'smb1' })
[void]$ctx.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))
$mMark = $ctx.Items.Add('Mark / unmark (Space)')
$mMark.add_Click({ Toggle-MarkSelected })
$mCopy = $ctx.Items.Add('Copy summary')
$mCopy.add_Click({ Copy-SelectedSummary })
$mCopyHex = $ctx.Items.Add('Copy hex dump')
$mCopyHex.add_Click({ if ($script:hexBox.Text) { [System.Windows.Forms.Clipboard]::SetText($script:hexBox.Text) } })
$script:lvPackets.ContextMenuStrip = $ctx
$splitH.Panel1.Controls.Add($script:lvPackets)

$splitV = New-Object System.Windows.Forms.SplitContainer
$splitV.Dock = 'Fill'
$splitV.Orientation = 'Vertical'
$splitV.SplitterWidth = 6
$splitV.BackColor = $script:C.Split

$script:tvDetails = New-Object System.Windows.Forms.TreeView
$script:tvDetails.Dock = 'Fill'
$script:tvDetails.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$script:tvDetails.HideSelection = $false
$script:tvDetails.ShowNodeToolTips = $true
$script:tvDetails.Add_NodeMouseClick({
    param($s, $e)
    if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Right -and $e.Node) {
        $txt = $e.Node.Text
        if ($txt -match '(\d+\.\d+\.\d+\.\d+)') {
            Set-DisplayFilter -Text ("ip.addr=={0}" -f $Matches[1])
        }
    }
})
$splitV.Panel1.Controls.Add($script:tvDetails)

$script:hexBox = New-Object System.Windows.Forms.RichTextBox
$script:hexBox.Dock = 'Fill'
$script:hexBox.Font = New-Object System.Drawing.Font('Consolas', 9)
$script:hexBox.ReadOnly = $true
$script:hexBox.WordWrap = $false
$script:hexBox.BackColor = [System.Drawing.Color]::FromArgb(250, 250, 252)
$script:hexBox.DetectUrls = $false
$splitV.Panel2.Controls.Add($script:hexBox)
$splitH.Panel2.Controls.Add($splitV)
$script:tabCapture.Controls.Add($splitH)

# --- Hosts tab ---
$hostTop = New-Object System.Windows.Forms.Panel
$hostTop.Dock = 'Top'
$hostTop.Height = 48
$hostTop.Padding = New-Object System.Windows.Forms.Padding(8)

$btnRes = New-FlatButton -Text 'Resolve DNS' -Width 120 -BackColor $script:C.Blue -OnClick { Resolve-HostNames } -TipText 'PTR lookup for each SMBv1 IP'
$btnRes.Location = New-Object System.Drawing.Point(8, 8)
$btnExpH = New-FlatButton -Text 'Export CSV' -Width 120 -BackColor $script:C.Dark -OnClick { Export-HostsCsv }
$btnExpH.Location = New-Object System.Drawing.Point(136, 8)
$btnFiltH = New-FlatButton -Text 'Filter selected IP' -Width 150 -BackColor $script:C.Teal -OnClick {
    if ($script:dgvHosts.SelectedRows.Count -gt 0) {
        $ip = $script:dgvHosts.SelectedRows[0].Cells['IP'].Value
        $script:tabMain.SelectedTab = $script:tabCapture
        Set-DisplayFilter -Text ("smb1 and ip.addr=={0}" -f $ip)
    }
}
$btnFiltH.Location = New-Object System.Drawing.Point(264, 8)
$hostTop.Controls.AddRange(@($btnRes, $btnExpH, $btnFiltH))

$script:dgvHosts = New-Object System.Windows.Forms.DataGridView
$script:dgvHosts.Dock = 'Fill'
$script:dgvHosts.AllowUserToAddRows = $false
$script:dgvHosts.AllowUserToDeleteRows = $false
$script:dgvHosts.ReadOnly = $true
$script:dgvHosts.SelectionMode = 'FullRowSelect'
$script:dgvHosts.MultiSelect = $false
$script:dgvHosts.AutoSizeColumnsMode = 'Fill'
$script:dgvHosts.BackgroundColor = $script:C.White
$script:dgvHosts.BorderStyle = 'None'
$script:dgvHosts.EnableHeadersVisualStyles = $false
$script:dgvHosts.ColumnHeadersDefaultCellStyle.BackColor = $script:C.Header
$script:dgvHosts.ColumnHeadersDefaultCellStyle.ForeColor = $script:C.White
$script:dgvHosts.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$script:dgvHosts.ColumnHeadersHeight = 30
$script:dgvHosts.RowTemplate.Height = 26
$script:dgvHosts.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(248, 250, 252)
foreach ($col in @('IP','HostName','Role','Packets','FirstSeen','LastSeen','Users','Shares','Commands','Sample')) {
    [void]$script:dgvHosts.Columns.Add($col, $col)
}
$script:dgvHosts.Add_CellDoubleClick({
    if ($script:dgvHosts.SelectedRows.Count -gt 0) {
        $ip = $script:dgvHosts.SelectedRows[0].Cells['IP'].Value
        $script:tabMain.SelectedTab = $script:tabCapture
        Set-DisplayFilter -Text ("smb1 and ip.addr=={0}" -f $ip)
    }
})
$script:tabHosts.Controls.Add($script:dgvHosts)
$script:tabHosts.Controls.Add($hostTop)

# --- Stats ---
$script:txtStats = New-Object System.Windows.Forms.TextBox
$script:txtStats.Dock = 'Fill'
$script:txtStats.Multiline = $true
$script:txtStats.ScrollBars = 'Both'
$script:txtStats.ReadOnly = $true
$script:txtStats.Font = New-Object System.Drawing.Font('Consolas', 10)
$script:txtStats.BackColor = [System.Drawing.Color]::FromArgb(18, 22, 28)
$script:txtStats.ForeColor = [System.Drawing.Color]::FromArgb(180, 230, 180)
$script:txtStats.WordWrap = $false
$script:tabStats.Controls.Add($script:txtStats)

# --- Config ---
$cfgTop = New-Object System.Windows.Forms.Panel
$cfgTop.Dock = 'Top'
$cfgTop.Height = 48
$btnCfg = New-FlatButton -Text 'Refresh config' -Width 140 -BackColor $script:C.Blue -OnClick { Refresh-ConfigTab }
$btnCfg.Location = New-Object System.Drawing.Point(8, 8)
$btnDis = New-FlatButton -Text 'Disable SMBv1 on this server' -Width 240 -BackColor $script:C.Red -OnClick { Disable-Smb1OnThisServer } -TipText 'Set-SmbServerConfiguration + registry SMB1=0. Double confirmation. Reboot required.'
$btnDis.Location = New-Object System.Drawing.Point(156, 8)
$cfgTop.Controls.AddRange(@($btnCfg, $btnDis))
$script:txtConfig = New-Object System.Windows.Forms.TextBox
$script:txtConfig.Dock = 'Fill'
$script:txtConfig.Multiline = $true
$script:txtConfig.ScrollBars = 'Both'
$script:txtConfig.ReadOnly = $true
$script:txtConfig.Font = New-Object System.Drawing.Font('Consolas', 10)
$script:txtConfig.BackColor = $script:C.White
$script:txtConfig.WordWrap = $false
$script:tabConfig.Controls.Add($script:txtConfig)
$script:tabConfig.Controls.Add($cfgTop)

# --- Events ---
$evTop = New-Object System.Windows.Forms.Panel
$evTop.Dock = 'Top'
$evTop.Height = 48
$lblH = New-Object System.Windows.Forms.Label
$lblH.Text = 'Look back (hours)'
$lblH.AutoSize = $true
$lblH.Location = New-Object System.Drawing.Point(12, 14)
$script:numHours = New-Object System.Windows.Forms.NumericUpDown
$script:numHours.Minimum = 1
$script:numHours.Maximum = 168
$script:numHours.Value = 24
$script:numHours.Location = New-Object System.Drawing.Point(130, 10)
$script:numHours.Width = 60
$btnScan = New-FlatButton -Text 'Scan SMB event logs' -Width 180 -BackColor $script:C.Blue -OnClick { Scan-SmbEventLogs }
$btnScan.Location = New-Object System.Drawing.Point(210, 8)
$evTop.Controls.AddRange(@($lblH, $script:numHours, $btnScan))
$script:dgvEvents = New-Object System.Windows.Forms.DataGridView
$script:dgvEvents.Dock = 'Fill'
$script:dgvEvents.AllowUserToAddRows = $false
$script:dgvEvents.ReadOnly = $true
$script:dgvEvents.SelectionMode = 'FullRowSelect'
$script:dgvEvents.AutoSizeColumnsMode = 'Fill'
$script:dgvEvents.BackgroundColor = $script:C.White
$script:dgvEvents.EnableHeadersVisualStyles = $false
$script:dgvEvents.ColumnHeadersDefaultCellStyle.BackColor = $script:C.Header
$script:dgvEvents.ColumnHeadersDefaultCellStyle.ForeColor = $script:C.White
$script:dgvEvents.ColumnHeadersHeight = 30
foreach ($col in @('Time','Log','Id','Level','Message')) { [void]$script:dgvEvents.Columns.Add($col, $col) }
$script:dgvEvents.Columns['Message'].FillWeight = 50
$script:tabEvents.Controls.Add($script:dgvEvents)
$script:tabEvents.Controls.Add($evTop)

# --- Help / Log ---
$txtHelp = New-Object System.Windows.Forms.TextBox
$txtHelp.Dock = 'Fill'
$txtHelp.Multiline = $true
$txtHelp.ScrollBars = 'Both'
$txtHelp.ReadOnly = $true
$txtHelp.Font = New-Object System.Drawing.Font('Consolas', 9.5)
$txtHelp.Text = Get-HelpText
$txtHelp.BackColor = $script:C.White
$script:tabHelp.Controls.Add($txtHelp)

$script:txtLog = New-Object System.Windows.Forms.TextBox
$script:txtLog.Dock = 'Fill'
$script:txtLog.Multiline = $true
$script:txtLog.ScrollBars = 'Vertical'
$script:txtLog.ReadOnly = $true
$script:txtLog.Font = New-Object System.Drawing.Font('Consolas', 9)
$script:txtLog.BackColor = [System.Drawing.Color]::FromArgb(18, 22, 28)
$script:txtLog.ForeColor = [System.Drawing.Color]::FromArgb(200, 220, 200)
$script:tabLog.Controls.Add($script:txtLog)

# --- Status bar ---
$status = New-Object System.Windows.Forms.Panel
$status.Dock = 'Bottom'
$status.Height = 28
$status.BackColor = $script:C.Header

function New-StatusLabel {
    param($Text, $Width, $X, $Color)
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $Text
    $l.ForeColor = $Color
    $l.AutoSize = $false
    $l.Width = $Width
    $l.Height = 28
    $l.TextAlign = 'MiddleLeft'
    $l.Location = New-Object System.Drawing.Point($X, 0)
    $l.Font = New-Object System.Drawing.Font('Segoe UI', 8.5)
    return $l
}
$script:lblState    = New-StatusLabel -Text 'Idle' -Width 110 -X 8 -Color $script:C.OkGreen
$script:lblPkt      = New-StatusLabel -Text 'Packets: 0   Shown: 0' -Width 280 -X 120 -Color $script:C.White
$script:lblSmb1     = New-StatusLabel -Text 'SMBv1: 0' -Width 110 -X 410 -Color [System.Drawing.Color]::FromArgb(180, 200, 180)
$script:lblDrop     = New-StatusLabel -Text 'Dropped: 0' -Width 110 -X 530 -Color $script:C.White
$script:lblHosts    = New-StatusLabel -Text 'SMBv1 hosts: 0' -Width 140 -X 650 -Color $script:C.White
$script:lblElapsed  = New-StatusLabel -Text 'Elapsed: --' -Width 140 -X 800 -Color $script:C.White
$script:lblStatusMini = New-StatusLabel -Text 'Ready' -Width 360 -X 950 -Color [System.Drawing.Color]::FromArgb(160, 185, 215)
$status.Controls.AddRange(@($script:lblState, $script:lblPkt, $script:lblSmb1, $script:lblDrop, $script:lblHosts, $script:lblElapsed, $script:lblStatusMini))

# --- Layout order: status (bottom), header/tool/filter/banners (top), tabs fill ---
$form.Controls.Add($script:tabMain)
$form.Controls.Add($status)
$form.Controls.Add($script:banner)
$form.Controls.Add($script:adminHint)
$form.Controls.Add($filterBar)
$form.Controls.Add($tool)
$form.Controls.Add($header)

# --- Menu ---
$menu = New-Object System.Windows.Forms.MenuStrip
function Add-MenuAction {
    param($ParentItems, [string]$Text, [scriptblock]$Action)
    $item = $ParentItems.Add($Text)
    $item.Add_Click($Action) | Out-Null
}

$fileM = New-Object System.Windows.Forms.ToolStripMenuItem('File')
Add-MenuAction $fileM.DropDownItems 'Open PCAP...' { Open-PcapFile }
Add-MenuAction $fileM.DropDownItems 'Save current view...' { Save-PcapFile }
Add-MenuAction $fileM.DropDownItems 'Load demo capture' { Import-DemoCapture }
[void]$fileM.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripSeparator))
Add-MenuAction $fileM.DropDownItems 'Exit' { $script:MainForm.Close() }
$capM = New-Object System.Windows.Forms.ToolStripMenuItem('Capture')
Add-MenuAction $capM.DropDownItems 'Start' { Start-Capture }
Add-MenuAction $capM.DropDownItems 'Stop' { Stop-Capture }
Add-MenuAction $capM.DropDownItems 'Pause / Resume' { Toggle-Pause }
Add-MenuAction $capM.DropDownItems 'Clear' { Clear-Capture }
$navM = New-Object System.Windows.Forms.ToolStripMenuItem('Go')
Add-MenuAction $navM.DropDownItems 'Go to packet...' { Show-GotoPacket }
Add-MenuAction $navM.DropDownItems 'Follow stream' { Use-FollowStream }
$helpM = New-Object System.Windows.Forms.ToolStripMenuItem('Help')
Add-MenuAction $helpM.DropDownItems 'Open Help tab' { $script:tabMain.SelectedTab = $script:tabHelp }
Add-MenuAction $helpM.DropDownItems 'About' {
    [void][System.Windows.Forms.MessageBox]::Show(
        "SMBv1 Traffic Analyzer v$($script:AppVersion)`nWindows PowerShell 5.1  |  Server 2012 R2+`n`nLive capture uses a raw IPv4 socket (no Npcap).`nExported PCAPs open in Wireshark.",
        'About',
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information)
}
[void]$menu.Items.AddRange(@($fileM, $capM, $navM, $helpM))
$form.MainMenuStrip = $menu
$form.Controls.Add($menu)

# --- Keyboard ---
$form.Add_KeyDown({
    param($s, $e)
    if ($e.Control -and $e.KeyCode -eq 'E') {
        if ($script:Engine.Running) { Stop-Capture } else { Start-Capture }
        $e.Handled = $true
    }
    elseif ($e.Control -and $e.KeyCode -eq 'L') { $script:txtFilter.Focus(); $e.Handled = $true }
    elseif ($e.Control -and $e.KeyCode -eq 'F') { $script:txtFind.Focus(); $e.Handled = $true }
    elseif ($e.Control -and $e.KeyCode -eq 'G') { Show-GotoPacket; $e.Handled = $true }
    elseif ($e.Control -and $e.KeyCode -eq 'S') { Save-PcapFile; $e.Handled = $true }
    elseif ($e.Control -and $e.KeyCode -eq 'O') { Open-PcapFile; $e.Handled = $true }
})

$form.Add_Shown({
    $splitH.SplitterDistance = [Math]::Max(220, [int]($splitH.Height * 0.48))
    $splitV.SplitterDistance = [Math]::Max(280, [int]($splitV.Width * 0.48))
    Update-FilterBarLayout
})
$form.Add_Resize({
    try { Update-FilterBarLayout } catch { }
})

$uiTimer = New-Object System.Windows.Forms.Timer
$uiTimer.Interval = 120
$uiTimer.Add_Tick({ Update-CaptureUi })
$uiTimer.Start()

$form.Add_FormClosing({
    $uiTimer.Stop()
    try { $script:Engine.Stop() } catch { }
})

Write-AppLog "SMBv1 Traffic Analyzer v$($script:AppVersion) started. Elevated=$($script:IsAdmin)  Host=$env:COMPUTERNAME" 'INFO'
Write-AppLog 'Pick an interface and click Start, or load the Demo capture / a PCAP.' 'INFO'
Refresh-ConfigTab
Update-StatsTab

if ($OpenPcap -and (Test-Path -LiteralPath $OpenPcap)) {
    Import-PcapPath -Path $OpenPcap
}

[void]$form.ShowDialog()
try { $script:Engine.Stop() } catch { }
try { $uiTimer.Dispose() } catch { }
