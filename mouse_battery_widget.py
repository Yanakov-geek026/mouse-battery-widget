#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Виджет заряда беспроводной мыши ARDOR GAMING "Phantom PRO v2" (2.4G Wireless).

Дизайн: компактная тёмная плашка — слева кольцо прогресса с иконкой мыши,
справа процент заряда. Несколько устройств выводятся строками друг под другом.
Показывается поверх всех окон, перетаскивается мышью, по правому клику — меню.
Размер меняется перетаскиванием правого нижнего уголка, Ctrl+колесом или
через меню (60–300%), и запоминается.

Заряд читается напрямую из нативного драйвера вендора HIDUsb.dll
(извлекается из "Mouse Drive Beta.exe", если файла нет рядом).

Иконки мыши/клавиатуры: Tabler Icons (MIT License) — https://tabler.io/icons
"""

import ctypes
import json
import math
import os
import queue
import re
import struct
import sys
import threading
import time
import xml.etree.ElementTree as ET
from ctypes import wintypes

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
POS_FILE = os.path.join(BASE_DIR, "widget_pos.json")
DLL_PATH = os.path.join(BASE_DIR, "HIDUsb.dll")
VENDOR_EXE = r"C:\Program Files (x86)\Phantom_PRO_V2_wireless\Mouse Drive Beta.exe"

VID = 0x3554
MOUSE_PID = 0xF52E
DONGLE_PID = 0xF52D

POLL_INTERVAL_S = 20.0     # период опроса заряда

try:
    from PIL import Image, ImageDraw, ImageFilter, ImageFont
except ImportError:                                    # pragma: no cover
    Image = None


# ===========================================================================
# 1. Извлечение HIDUsb.dll (x64) из программы вендора, если файла нет рядом
# ===========================================================================

def _pe_exports(blob):
    """Вернуть (machine, size_of_image, list_of_export_names) для PE-образа."""
    if blob[:2] != b"MZ":
        return None
    e = struct.unpack_from("<I", blob, 0x3C)[0]
    if blob[e:e + 4] != b"PE\x00\x00":
        return None
    coff = e + 4
    machine = struct.unpack_from("<H", blob, coff)[0]
    ns = struct.unpack_from("<H", blob, coff + 2)[0]
    optsz = struct.unpack_from("<H", blob, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", blob, opt)[0]
    size_of_image = struct.unpack_from("<I", blob, opt + 56)[0]
    sec = opt + optsz
    sections = []
    for i in range(ns):
        s = sec + i * 40
        name = blob[s:s + 8].rstrip(b"\x00").decode("ascii", "ignore")
        vsize = struct.unpack_from("<I", blob, s + 8)[0]
        vaddr = struct.unpack_from("<I", blob, s + 12)[0]
        rsize = struct.unpack_from("<I", blob, s + 16)[0]
        rptr = struct.unpack_from("<I", blob, s + 20)[0]
        sections.append((name, vaddr, vsize, rptr, rsize))

    def r2o(rva):
        for _, vaddr, vsize, rptr, rsize in sections:
            if vaddr <= rva < vaddr + max(vsize, rsize):
                return rptr + (rva - vaddr)
        return None

    dd = opt + (96 if magic == 0x10b else 112)
    exp_rva, exp_size = struct.unpack_from("<II", blob, dd)
    exports = []
    if exp_rva:
        def rd32(rva):
            off = r2o(rva)
            if off is None or off + 4 > len(blob):
                return 0
            return struct.unpack_from("<I", blob, off)[0]
        n_names = rd32(exp_rva + 24)
        names_rva = rd32(exp_rva + 32)
        for i in range(min(n_names, 400)):
            nrva = struct.unpack_from("<I", blob, r2o(names_rva + i * 4))[0]
            noff = r2o(nrva)
            end = blob.find(b"\x00", noff)
            exports.append(blob[noff:end].decode("ascii", "ignore"))
    return machine, size_of_image, exports


def ensure_dll():
    """Убедиться, что рядом лежит x64 HIDUsb.dll; при необходимости извлечь."""
    if os.path.exists(DLL_PATH):
        return True
    if not os.path.exists(VENDOR_EXE):
        return False
    data = open(VENDOR_EXE, "rb").read()
    for m in re.finditer(rb"MZ", data):
        off = m.start()
        try:
            e = struct.unpack_from("<I", data, off + 0x3C)[0]
            if not (0 < e < 0x100000):
                continue
            if data[off + e:off + e + 4] != b"PE\x00\x00":
                continue
            info = _pe_exports(data[off:])
            if not info:
                continue
            machine, size, exports = info
            if machine == 0x8664 and "CS_UsbServer_ReadBatteryLevel" in exports:
                open(DLL_PATH, "wb").write(data[off:off + size])
                return True
        except Exception:
            continue
    return False


# ===========================================================================
# 2. Поиск HID-пути управляющего канала донглера (MI_01 Col05)
# ===========================================================================

class GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16),
                ("Data3", ctypes.c_uint16), ("Data4", ctypes.c_ubyte * 8)]


class SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("InterfaceClassGuid", GUID),
                ("Flags", wintypes.DWORD), ("Reserved", ctypes.c_void_p)]


class SP_DEVICE_INTERFACE_DETAIL_DATA(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("DevicePath", wintypes.WCHAR * 1)]


class HIDD_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Size", wintypes.DWORD), ("VendorID", wintypes.WORD),
                ("ProductID", wintypes.WORD), ("VersionNumber", wintypes.WORD)]


def find_control_path():
    """Найти путь HID-коллекции донглера (PID F52D, MI_01, Col05)."""
    guid = GUID(0x4D1E55B2, 0xF16F, 0x11CF,
                (ctypes.c_ubyte * 8)(0x88, 0xCB, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30))
    setupapi = ctypes.WinDLL("setupapi", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    hid = ctypes.WinDLL("hid", use_last_error=True)

    setupapi.SetupDiGetClassDevsW.argtypes = [ctypes.POINTER(GUID), wintypes.LPCWSTR, wintypes.HWND, wintypes.DWORD]
    setupapi.SetupDiGetClassDevsW.restype = wintypes.HANDLE
    setupapi.SetupDiEnumDeviceInterfaces.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(GUID), wintypes.DWORD, ctypes.POINTER(SP_DEVICE_INTERFACE_DATA)]
    setupapi.SetupDiEnumDeviceInterfaces.restype = wintypes.BOOL
    setupapi.SetupDiGetDeviceInterfaceDetailW.argtypes = [wintypes.HANDLE, ctypes.POINTER(SP_DEVICE_INTERFACE_DATA), ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    setupapi.SetupDiGetDeviceInterfaceDetailW.restype = wintypes.BOOL
    setupapi.SetupDiDestroyDeviceInfoList.argtypes = [wintypes.HANDLE]
    setupapi.SetupDiDestroyDeviceInfoList.restype = wintypes.BOOL
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    hid.HidD_GetAttributes.argtypes = [wintypes.HANDLE, ctypes.POINTER(HIDD_ATTRIBUTES)]
    hid.HidD_GetAttributes.restype = wintypes.BOOL

    DIGCF_PRESENT, DIGCF_DEVICEINTERFACE = 0x2, 0x10
    GENERIC_READ, GENERIC_WRITE = 0x80000000, 0x40000000
    FILE_SHARE_READ, FILE_SHARE_WRITE = 1, 2
    OPEN_EXISTING = 3
    INVALID = ctypes.c_void_p(-1).value

    dev = setupapi.SetupDiGetClassDevsW(ctypes.byref(guid), None, None, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE)
    if dev == INVALID:
        return None
    found = []
    idx = 0
    while True:
        did = SP_DEVICE_INTERFACE_DATA()
        did.cbSize = ctypes.sizeof(did)
        if not setupapi.SetupDiEnumDeviceInterfaces(dev, None, ctypes.byref(guid), idx, ctypes.byref(did)):
            break
        idx += 1
        needed = wintypes.DWORD(0)
        setupapi.SetupDiGetDeviceInterfaceDetailW(dev, ctypes.byref(did), None, 0, ctypes.byref(needed), None)
        detail = (ctypes.c_ubyte * needed.value)()
        hdr = ctypes.cast(detail, ctypes.POINTER(SP_DEVICE_INTERFACE_DETAIL_DATA))
        hdr.contents.cbSize = ctypes.sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA)
        if not setupapi.SetupDiGetDeviceInterfaceDetailW(dev, ctypes.byref(did), detail, needed.value, None, None):
            continue
        off = SP_DEVICE_INTERFACE_DETAIL_DATA.DevicePath.offset
        path = ctypes.wstring_at(ctypes.cast(detail, ctypes.c_void_p).value + off)
        h = kernel32.CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None)
        if h == INVALID:
            continue
        attr = HIDD_ATTRIBUTES()
        attr.Size = ctypes.sizeof(attr)
        if hid.HidD_GetAttributes(h, ctypes.byref(attr)):
            if attr.VendorID == VID and attr.ProductID == DONGLE_PID:
                found.append(path)
        kernel32.CloseHandle(h)
    setupapi.SetupDiDestroyDeviceInfoList(dev)

    for p in found:
        if "mi_01&col05" in p.lower():
            return p
    return found[-1] if found else None


# ===========================================================================
# 3. Обёртка над HIDUsb.dll
# ===========================================================================

class BatteryReader:
    OnUsbDataReceived = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_int)

    class BatteryStatus(ctypes.Structure):
        _pack_ = 1
        _fields_ = [("level", ctypes.c_ubyte), ("isCharging", ctypes.c_ubyte), ("BatVoltage", ctypes.c_ushort)]

    def __init__(self, path):
        self.path = path
        self.lib = ctypes.CDLL(DLL_PATH)
        self.captured = {}
        self._cb = self.OnUsbDataReceived(self._on_data)

        self.lib.CS_UsbServer_SetVidPid.argtypes = [ctypes.c_int, ctypes.c_int]
        self.lib.CS_UsbServer_SetVidPid.restype = None
        self.lib.CS_UsbServer_Start.argtypes = [ctypes.c_char_p, ctypes.c_char_p, self.OnUsbDataReceived]
        self.lib.CS_UsbServer_Start.restype = None
        self.lib.CS_UsbServer_ReadBatteryLevel.argtypes = []
        self.lib.CS_UsbServer_ReadBatteryLevel.restype = None
        self.lib.CS_UsbServer_Exit.argtypes = []
        self.lib.CS_UsbServer_Exit.restype = None
        self.lib.CS_GetDeviceBatteryStatus.argtypes = [ctypes.c_char_p, ctypes.POINTER(self.BatteryStatus)]
        self.lib.CS_GetDeviceBatteryStatus.restype = None

    def _on_data(self, pcmd, cmdLength, pdata, dataLength):
        self.captured["data"] = ctypes.string_at(pdata, dataLength) if (pdata and dataLength > 0) else b""
        self.captured["fired"] = True

    def start(self):
        in_ep = ctypes.create_string_buffer(self.path.encode("ascii", "ignore"), 1024)
        out_ep = ctypes.create_string_buffer(self.path.encode("ascii", "ignore"), 1024)
        self.lib.CS_UsbServer_SetVidPid(VID, MOUSE_PID)
        self.lib.CS_UsbServer_Start(in_ep, out_ep, self._cb)

    def read(self, timeout=2.0):
        """Вернуть (level, isCharging, voltage_mV) или None при таймауте.

        Одиночный ответ может оказаться служебным пакетом (например,
        подтверждением соединения), поэтому проверяем правдоподобность
        значений и при необходимости повторяем запрос.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.captured.clear()
            self.lib.CS_UsbServer_ReadBatteryLevel()
            step_deadline = min(deadline, time.time() + 0.45)
            while time.time() < step_deadline:
                if self.captured.get("fired"):
                    break
                time.sleep(0.02)
            data = self.captured.get("data", b"")
            if len(data) >= 4:
                bs = self.BatteryStatus()
                self.lib.CS_GetDeviceBatteryStatus(data, ctypes.byref(bs))
                if bs.level <= 100 and 1000 <= bs.BatVoltage <= 6000:
                    return bs.level, bs.isCharging, bs.BatVoltage
            time.sleep(0.12)
        return None

    def stop(self):
        try:
            self.lib.CS_UsbServer_Exit()
        except Exception:
            pass


# ===========================================================================
# 4. Мини-рендерер SVG (нужен только для иконок — Tabler Icons)
# ===========================================================================

_SVG_TOKEN = re.compile(r"[MmLlHhVvCcSsQqTtAaZz]|[-+]?(?:\d*\.\d+|\d+\.?)(?:[eE][-+]?\d+)?")
_NUM_ONLY = re.compile(r"[-+]?(?:\d*\.\d+|\d+\.?)(?:[eE][-+]?\d+)?")

_FALLBACK_SVG = {
    "mouse.svg": (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" '
        'stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M6 7a4 4 0 0 1 4 -4h4a4 4 0 0 1 4 4v10a4 4 0 0 1 -4 4h-4a4 4 0 0 1 -4 -4l0 -10"/>'
        '<path d="M12 7l0 4"/></svg>'
    ),
    "keyboard.svg": (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" '
        'stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M2 8a2 2 0 0 1 2 -2h16a2 2 0 0 1 2 2v8a2 2 0 0 1 -2 2h-16a2 2 0 0 1 -2 -2l0 -8"/>'
        '<path d="M6 10l0 .01"/><path d="M10 10l0 .01"/><path d="M14 10l0 .01"/>'
        '<path d="M18 10l0 .01"/><path d="M6 14l0 .01"/><path d="M18 14l0 .01"/>'
        '<path d="M10 14l4 .01"/></svg>'
    ),
}


def _cubic(p0, p1, p2, p3, n=24):
    out = []
    for k in range(1, n + 1):
        t = k / n
        mt = 1.0 - t
        a, b, c, d = mt ** 3, 3 * mt * mt * t, 3 * mt * t * t, t ** 3
        out.append((a * p0[0] + b * p1[0] + c * p2[0] + d * p3[0],
                    a * p0[1] + b * p1[1] + c * p2[1] + d * p3[1]))
    return out


def _quad(p0, p1, p2, n=20):
    out = []
    for k in range(1, n + 1):
        t = k / n
        mt = 1.0 - t
        out.append((mt * mt * p0[0] + 2 * mt * t * p1[0] + t * t * p2[0],
                    mt * mt * p0[1] + 2 * mt * t * p1[1] + t * t * p2[1]))
    return out


def _arc_points(x1, y1, rx, ry, phi_deg, large, sweep, x2, y2, n=28):
    """Эллиптическая дуга SVG (endpoint -> center параметризация)."""
    rx, ry = abs(float(rx)), abs(float(ry))
    if rx == 0 or ry == 0:
        return [(x2, y2)]
    phi = math.radians(phi_deg)
    cosp, sinp = math.cos(phi), math.sin(phi)
    dx, dy = (x1 - x2) / 2.0, (y1 - y2) / 2.0
    x1p = cosp * dx + sinp * dy
    y1p = -sinp * dx + cosp * dy
    lam = (x1p * x1p) / (rx * rx) + (y1p * y1p) / (ry * ry)
    if lam > 1.0:
        s = math.sqrt(lam)
        rx *= s
        ry *= s
    num = rx * rx * ry * ry - rx * rx * y1p * y1p - ry * ry * x1p * x1p
    den = rx * rx * y1p * y1p + ry * ry * x1p * x1p
    coef = math.sqrt(max(0.0, num / den)) if den else 0.0
    if bool(large) == bool(sweep):
        coef = -coef
    cxp = coef * rx * y1p / ry
    cyp = -coef * ry * x1p / rx
    cx = cosp * cxp - sinp * cyp + (x1 + x2) / 2.0
    cy = sinp * cxp + cosp * cyp + (y1 + y2) / 2.0

    def ang(ux, uy, vx, vy):
        dot = ux * vx + uy * vy
        nn = math.hypot(ux, uy) * math.hypot(vx, vy)
        if nn == 0:
            return 0.0
        a = math.acos(max(-1.0, min(1.0, dot / nn)))
        return -a if (ux * vy - uy * vx) < 0 else a

    ux, uy = (x1p - cxp) / rx, (y1p - cyp) / ry
    vx, vy = (-x1p - cxp) / rx, (-y1p - cyp) / ry
    th1 = ang(1, 0, ux, uy)
    dth = ang(ux, uy, vx, vy)
    if not sweep and dth > 0:
        dth -= 2 * math.pi
    if sweep and dth < 0:
        dth += 2 * math.pi
    pts = []
    for i in range(1, n + 1):
        t = th1 + dth * i / n
        x = cx + rx * math.cos(t) * cosp - ry * math.sin(t) * sinp
        y = cy + rx * math.cos(t) * sinp + ry * math.sin(t) * cosp
        pts.append((x, y))
    return pts


def _parse_path(d):
    """Разобрать d= у path в список (точки, замкнут)."""
    toks = _SVG_TOKEN.findall(d or "")
    subs = []
    pts = []
    cur = [0.0, 0.0]
    start = [0.0, 0.0]
    cmd = None
    last_ctrl = None
    i = 0

    def num():
        nonlocal i
        v = float(toks[i])
        i += 1
        return v

    def end_sub(closed):
        nonlocal pts
        if len(pts) > 1:
            subs.append((list(pts), closed))
        pts = []

    while i < len(toks):
        t = toks[i]
        if t.isalpha():
            cmd = t
            i += 1
            if cmd in "Zz":
                if pts:
                    pts.append((start[0], start[1]))
                end_sub(True)
                cur = list(start)
                last_ctrl = None
                continue
        if cmd is None:
            i += 1
            continue
        c = cmd
        try:
            if c in "Mm":
                x, y = num(), num()
                if c == "m":
                    x += cur[0]
                    y += cur[1]
                end_sub(False)
                cur = [x, y]
                start = [x, y]
                pts = [(x, y)]
                cmd = "L" if c == "M" else "l"
            elif c in "Ll":
                x, y = num(), num()
                if c == "l":
                    x += cur[0]
                    y += cur[1]
                cur = [x, y]
                pts.append((x, y))
            elif c in "Hh":
                x = num()
                if c == "h":
                    x += cur[0]
                cur = [x, cur[1]]
                pts.append((x, cur[1]))
            elif c in "Vv":
                y = num()
                if c == "v":
                    y += cur[1]
                cur = [cur[0], y]
                pts.append((cur[0], y))
            elif c in "Cc":
                x1, y1, x2, y2, x, y = (num() for _ in range(6))
                if c == "c":
                    x1 += cur[0]; y1 += cur[1]
                    x2 += cur[0]; y2 += cur[1]
                    x += cur[0]; y += cur[1]
                pts.extend(_cubic(tuple(cur), (x1, y1), (x2, y2), (x, y)))
                last_ctrl = (x2, y2)
                cur = [x, y]
            elif c in "Ss":
                x2, y2, x, y = (num() for _ in range(4))
                if c == "s":
                    x2 += cur[0]; y2 += cur[1]
                    x += cur[0]; y += cur[1]
                if last_ctrl:
                    c1 = (2 * cur[0] - last_ctrl[0], 2 * cur[1] - last_ctrl[1])
                else:
                    c1 = (cur[0], cur[1])
                pts.extend(_cubic(tuple(cur), c1, (x2, y2), (x, y)))
                last_ctrl = (x2, y2)
                cur = [x, y]
            elif c in "Qq":
                x1, y1, x, y = (num() for _ in range(4))
                if c == "q":
                    x1 += cur[0]; y1 += cur[1]
                    x += cur[0]; y += cur[1]
                pts.extend(_quad(tuple(cur), (x1, y1), (x, y)))
                last_ctrl = (x1, y1)
                cur = [x, y]
            elif c in "Tt":
                x, y = num(), num()
                if c == "t":
                    x += cur[0]; y += cur[1]
                if last_ctrl:
                    c1 = (2 * cur[0] - last_ctrl[0], 2 * cur[1] - last_ctrl[1])
                else:
                    c1 = (cur[0], cur[1])
                pts.extend(_quad(tuple(cur), c1, (x, y)))
                last_ctrl = c1
                cur = [x, y]
            elif c in "Aa":
                rx, ry, rot, laf, sf, x, y = (num() for _ in range(7))
                if c == "a":
                    x += cur[0]; y += cur[1]
                pts.extend(_arc_points(cur[0], cur[1], rx, ry, rot, int(laf), int(sf), x, y))
                cur = [x, y]
            else:
                i += 1
            if c not in "CcSsQqTt":
                last_ctrl = None
        except IndexError:
            break
    end_sub(False)
    return subs


def _round_rect_pts(x, y, w, h, rx, ry):
    pts = []

    def arc(cx, cy, a0, a1):
        for k in range(1, 9):
            t = math.radians(a0 + (a1 - a0) * k / 8.0)
            pts.append((cx + rx * math.cos(t), cy + ry * math.sin(t)))

    arc(x + w - rx, y + ry, -90, 0)
    arc(x + w - rx, y + h - ry, 0, 90)
    arc(x + rx, y + h - ry, 90, 180)
    arc(x + rx, y + ry, 180, 270)
    return pts


def _element_subpaths(tag, a):
    tag = tag.lower()
    try:
        if tag == "rect":
            x = float(a.get("x", 0) or 0)
            y = float(a.get("y", 0) or 0)
            w = float(a.get("width", 0) or 0)
            h = float(a.get("height", 0) or 0)
            rx = float(a.get("rx", 0) or 0)
            ry = float(a.get("ry", rx) or rx)
            if rx <= 0 and ry <= 0:
                return [([(x, y), (x + w, y), (x + w, y + h), (x, y + h)], True)]
            rx = min(rx, w / 2.0)
            ry = min(ry, h / 2.0)
            return [(_round_rect_pts(x, y, w, h, rx, ry), True)]
        if tag in ("circle", "ellipse"):
            cx = float(a.get("cx", 0) or 0)
            cy = float(a.get("cy", 0) or 0)
            r = float(a.get("r", 0) or 0)
            rx = float(a.get("rx", r) or r)
            ry = float(a.get("ry", r) or r)
            pts = [(cx + rx * math.cos(2 * math.pi * k / 64.0),
                    cy + ry * math.sin(2 * math.pi * k / 64.0)) for k in range(64)]
            return [(pts, True)]
        if tag == "line":
            return [([(float(a.get("x1", 0) or 0), float(a.get("y1", 0) or 0)),
                      (float(a.get("x2", 0) or 0), float(a.get("y2", 0) or 0))], False)]
        if tag in ("polyline", "polygon"):
            nums = [float(v) for v in _NUM_ONLY.findall(a.get("points", ""))]
            pts = list(zip(nums[0::2], nums[1::2]))
            return [(pts, tag == "polygon")]
        if tag == "path":
            return _parse_path(a.get("d", ""))
    except Exception:
        return []
    return []


class SvgIcon:
    def __init__(self, text):
        root = ET.fromstring(text)
        vb = (root.get("viewBox") or "0 0 24 24").replace(",", " ").split()
        self.vb = [float(v) for v in vb]
        self.stroke = float(root.get("stroke-width", 2) or 2)
        self.items = []
        for el in root:
            tag = el.tag.split("}")[-1]
            if tag in ("title", "desc", "defs", "style", "metadata"):
                continue
            a = {k.split("}")[-1]: v for k, v in el.attrib.items()}
            fill = a.get("fill", root.get("fill", "none"))
            self.items.append((_element_subpaths(tag, a), fill))

    def render(self, px, color=(255, 255, 255, 255), stroke_units=None, ss=4):
        px = max(2, int(round(px)))
        size = px * ss
        vw = self.vb[2] - self.vb[0]
        vh = self.vb[3] - self.vb[1]
        sc = size / max(vw, vh)
        off_x = (size - vw * sc) / 2.0
        off_y = (size - vh * sc) / 2.0
        layer = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        d = ImageDraw.Draw(layer)
        wpx = (stroke_units if stroke_units is not None else self.stroke) * sc
        for subs, fill in self.items:
            tr = []
            for pts, closed in subs:
                tr.append(([(off_x + (x - self.vb[0]) * sc, off_y + (y - self.vb[1]) * sc)
                            for (x, y) in pts], closed))
            if fill not in (None, "none", "transparent"):
                for pts, closed in tr:
                    if len(pts) >= 3:
                        d.polygon(pts, fill=color)
                continue
            for pts, closed in tr:
                if len(pts) == 1:
                    r = wpx / 2.0
                    d.ellipse([pts[0][0] - r, pts[0][1] - r, pts[0][0] + r, pts[0][1] + r], fill=color)
                    continue
                if closed and pts[0] != pts[-1]:
                    pts = pts + [pts[0]]
                d.line(pts, fill=color, width=max(1, int(round(wpx))), joint="curve")
                if not closed:
                    r = wpx / 2.0
                    for p in (pts[0], pts[-1]):
                        d.ellipse([p[0] - r, p[1] - r, p[0] + r, p[1] + r], fill=color)
        return layer.resize((px, px), Image.LANCZOS)


_ICONS = {}
_ICON_IMAGES = {}


def load_icon(name):
    if name in _ICONS:
        return _ICONS[name]
    text = None
    path = os.path.join(ASSETS_DIR, name)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
        except OSError:
            text = None
    if not text:
        text = _FALLBACK_SVG.get(name) or _FALLBACK_SVG["mouse.svg"]
    icon = SvgIcon(text)
    _ICONS[name] = icon
    return icon


def icon_image(name, px, color):
    key = (name, int(round(px)), tuple(color))
    img = _ICON_IMAGES.get(key)
    if img is None:
        img = load_icon(name).render(px, color, stroke_units=ICON_STROKE_UNITS)
        _ICON_IMAGES[key] = img
    return img


def fitted_image(name, height_px, color):
    """Иконка, обрезанная по содержимому и приведённая к нужной высоте."""
    key = (name, int(round(height_px)), tuple(color), "fit")
    img = _ICON_IMAGES.get(key)
    if img is not None:
        return img
    big = load_icon(name).render(max(8, int(round(height_px * 4))), color)
    bbox = big.getchannel("A").getbbox()
    if bbox:
        big = big.crop(bbox)
    w = max(1, int(round(big.width * height_px / max(1.0, big.height))))
    img = big.resize((w, max(1, int(round(height_px)))), Image.LANCZOS)
    _ICON_IMAGES[key] = img
    return img


# ===========================================================================
# 5. Дизайн виджета
# ===========================================================================

# --- геометрия в логических пикселях (96 dpi) ---
# Компактная горизонтальная плашка: слева кольцо с иконкой устройства,
# справа — процент. Несколько устройств выводятся строками друг под другом.
RING_D = 34.0          # диаметр кольца
RING_W = 4.0           # толщина кольца
PAD_X = 10.0           # отступ по бокам
PAD_Y = 8.0            # отступ сверху и снизу
GAP = 8.0              # от кольца до цифры
ROW_GAP = 12.0         # промежуток между строками устройств
FONT_PX = 21           # размер цифры процента (Segoe UI Semibold)
CARD_R = 12.0          # радиус скругления карточки
SHADOW_PAD = 12.0      # поле вокруг карточки под тень
SHADOW_DY = 2.0
SHADOW_BLUR = 6.0
ICON_BOX = 0.58        # размер иконки как доля RING_D
ICON_STROKE_UNITS = 1.20

# --- размеры окна ---
USER_SCALE_MIN = 0.60
USER_SCALE_MAX = 3.00
USER_SCALE_STEP = 0.10
USER_SCALE_DEFAULT = 1.00
GRIP_LOGICAL = 24.0    # сторона «уголка» для изменения размера, лог. px

# --- палитра (снята с макета) ---
C_CARD = (33, 30, 33, 255)          # #211E21
C_TRACK = (62, 59, 63, 255)         # #3E3B3F
C_GREEN = (49, 209, 93, 255)        # #31D15D
C_AMBER = (245, 186, 66, 255)
C_RED = (233, 84, 84, 255)
C_WHITE = (255, 254, 255, 255)

_FONTS = {}


def _font(px):
    f = _FONTS.get(px)
    if f is not None:
        return f
    windir = os.environ.get("WINDIR", r"C:\Windows")
    for name in ("seguisb.ttf", "segoeui.ttf", "arial.ttf"):
        p = os.path.join(windir, "Fonts", name)
        if os.path.exists(p):
            try:
                f = ImageFont.truetype(p, px)
                break
            except OSError:
                continue
    if f is None:
        f = ImageFont.load_default()
    _FONTS[px] = f
    return f


def level_color(level):
    if level is None:
        return (95, 95, 99, 255)
    if level >= 50:
        return C_GREEN
    if level >= 20:
        return C_AMBER
    return C_RED


_PCT_SIZE = None


def _pct_text_size():
    """Ширина/высота строки «100%» в логических пикселях (кэшируется)."""
    global _PCT_SIZE
    if _PCT_SIZE is None:
        font = _font(FONT_PX * 4)           # меряем крупно — точнее
        probe = Image.new("RGBA", (8, 8))
        bb = ImageDraw.Draw(probe).textbbox((0, 0), "100%", font=font)
        _PCT_SIZE = ((bb[2] - bb[0]) / 4.0, (bb[3] - bb[1]) / 4.0)
    return _PCT_SIZE


def card_size(n):
    tw, _th = _pct_text_size()
    return (PAD_X * 2 + RING_D + GAP + tw,
            PAD_Y * 2 + RING_D * n + ROW_GAP * (n - 1))


def widget_size_px(n, scale):
    cw, ch = card_size(n)
    return (int(round((cw + SHADOW_PAD * 2) * scale)),
            int(round((ch + SHADOW_PAD * 2) * scale)))


def _polar(cx, cy, r, angle_deg):
    a = math.radians(angle_deg)
    return (cx + r * math.sin(a), cy - r * math.cos(a))


def _ring(img, cx, cy, r, w, color, a0, a1):
    """Дуга кольца: 0° = вверх, по часовой стрелке."""
    span = a1 - a0
    if span <= 0.05:
        return
    mask = Image.new("L", img.size, 0)
    m = ImageDraw.Draw(mask)
    outer = [cx - r, cy - r, cx + r, cy + r]
    inner = [cx - (r - w), cy - (r - w), cx + (r - w), cy + (r - w)]
    if span >= 359.9:
        m.ellipse(outer, fill=255)
        m.ellipse(inner, fill=0)
    else:
        m.pieslice(outer, a0 - 90.0, a1 - 90.0, fill=255)
        m.pieslice(inner, a0 - 90.0, a1 - 90.0, fill=0)
        rm = r - w / 2.0
        for a in (a0, a1):
            px, py = _polar(cx, cy, rm, a)
            m.ellipse([px - w / 2.0, py - w / 2.0, px + w / 2.0, py + w / 2.0], fill=255)
    layer = Image.new("RGBA", img.size, color)
    img.paste(layer, (0, 0), mask)


def _bolt(img, cx, cy, ring_d, ring_r, S):
    """Значок молнии (зарядка) — поверх верхушки кольца, как на макете."""
    h = 0.24 * ring_d * S
    bolt = fitted_image("bolt.svg", h, C_WHITE)
    bx = int(round(cx - 0.10 * ring_d * S - bolt.width / 2.0))
    by = int(round((cy - ring_r) - 0.06 * ring_d * S))
    img.alpha_composite(bolt, (bx, by))


def _grip(img, x1, y1, S, alpha=58):
    """Тонкий «уголок» у правого нижнего края — подсказка, что за него тянут."""
    d = ImageDraw.Draw(img)
    col = (255, 255, 255, alpha)
    w = max(1, int(round(1.4 * S)))
    o, ln, shift = 9.0 * S, 7.0 * S, 3.2 * S
    for k in (0.0, shift):
        d.line([(x1 - o - ln - k, y1 - o + k), (x1 - o - k, y1 - o - ln + k)],
               fill=col, width=w)


def render_widget(states, scale=1.0, ss=3, grip=False):
    """Отрисовать виджет. states — список dict(level, charging, icon).
    grip=True — показать уголок изменения размера (при наведении).
    """
    if Image is None:
        raise RuntimeError("Pillow не установлен")
    n = max(1, len(states))
    cw, ch = card_size(n)
    S = scale * ss
    W = int(round((cw + SHADOW_PAD * 2) * S))
    H = int(round((ch + SHADOW_PAD * 2) * S))
    img = Image.new("RGBA", (W, H), (0, 0, 0, 0))

    ox = SHADOW_PAD * S
    oy = SHADOW_PAD * S
    x0, y0 = ox, oy
    x1, y1 = ox + cw * S, oy + ch * S

    # мягкая тень под карточкой
    sh = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ImageDraw.Draw(sh).rounded_rectangle(
        [x0, y0 + SHADOW_DY * S, x1, y1 + SHADOW_DY * S],
        radius=CARD_R * S, fill=(0, 0, 0, 105))
    sh = sh.filter(ImageFilter.GaussianBlur(SHADOW_BLUR * S))
    img = Image.alpha_composite(img, sh)

    d = ImageDraw.Draw(img)
    d.rounded_rectangle([x0, y0, x1, y1], radius=CARD_R * S, fill=C_CARD)

    # тончайшая светлая кромка
    edge = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ImageDraw.Draw(edge).rounded_rectangle(
        [x0, y0, x1, y1], radius=CARD_R * S,
        outline=(255, 255, 255, 12), width=max(1, int(round(S))))
    img = Image.alpha_composite(img, edge)
    d = ImageDraw.Draw(img)

    font = _font(int(round(FONT_PX * S)))
    for i, st in enumerate(states):
        cx = ox + (PAD_X + RING_D / 2.0) * S
        cy = oy + (PAD_Y + RING_D / 2.0 + i * (RING_D + ROW_GAP)) * S
        r_out = RING_D / 2.0 * S
        rw = RING_W * S
        level = st.get("level")

        _ring(img, cx, cy, r_out, rw, C_TRACK, 0, 360)
        if level:
            _ring(img, cx, cy, r_out, rw, level_color(level), 0, 360.0 * level / 100.0)

        # иконка внутри кольца
        ibox = RING_D * ICON_BOX * S
        icon_col = C_WHITE if level is not None else (255, 254, 255, 110)
        icon = icon_image(st.get("icon", "mouse.svg"), ibox, icon_col)
        img.alpha_composite(icon, (int(round(cx - ibox / 2.0)), int(round(cy - ibox / 2.0))))
        d = ImageDraw.Draw(img)

        # молния зарядки на верхушке кольца
        if st.get("charging") and level is not None:
            _bolt(img, cx, cy, RING_D, r_out, S)
            d = ImageDraw.Draw(img)

        # процент — справа от кольца, по вертикали по центру строки
        txt = "--%" if level is None else "%d%%" % level
        tx = ox + (PAD_X + RING_D + GAP) * S
        fill = C_WHITE if level is not None else (255, 254, 255, 130)
        d.text((tx, cy), txt, font=font, fill=fill, anchor="lm")

    # уголок для изменения размера (только когда курсор над ним)
    if grip:
        _grip(img, x1, y1, S, alpha=72)

    return img.resize(
        (int(round((cw + SHADOW_PAD * 2) * scale)),
         int(round((ch + SHADOW_PAD * 2) * scale))), Image.LANCZOS)


# ===========================================================================
# 6. Окно с попиксельной прозрачностью (UpdateLayeredWindow)
# ===========================================================================

user32 = ctypes.WinDLL("user32", use_last_error=True)
gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)

user32.GetDC.argtypes = [wintypes.HWND]
user32.GetDC.restype = wintypes.HDC
user32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
user32.ReleaseDC.restype = ctypes.c_int
user32.GetParent.argtypes = [wintypes.HWND]
user32.GetParent.restype = wintypes.HWND
user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
user32.GetAncestor.restype = wintypes.HWND
user32.GetDesktopWindow.restype = wintypes.HWND
user32.GetWindowLongW.argtypes = [wintypes.HWND, ctypes.c_int]
user32.GetWindowLongW.restype = wintypes.LONG
user32.SetWindowLongW.argtypes = [wintypes.HWND, ctypes.c_int, wintypes.LONG]
user32.SetWindowLongW.restype = wintypes.LONG
user32.UpdateLayeredWindow.argtypes = [
    wintypes.HWND, wintypes.HDC, ctypes.POINTER(wintypes.POINT),
    ctypes.POINTER(wintypes.SIZE), wintypes.HDC, ctypes.POINTER(wintypes.POINT),
    wintypes.COLORREF, ctypes.c_void_p, wintypes.DWORD]
user32.UpdateLayeredWindow.restype = wintypes.BOOL
user32.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
                                ctypes.c_int, ctypes.c_int, wintypes.UINT]
user32.SetWindowPos.restype = wintypes.BOOL
user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
user32.GetWindowRect.restype = wintypes.BOOL
gdi32.CreateCompatibleDC.argtypes = [wintypes.HDC]
gdi32.CreateCompatibleDC.restype = wintypes.HDC
gdi32.DeleteDC.argtypes = [wintypes.HDC]
gdi32.DeleteDC.restype = wintypes.BOOL
gdi32.SelectObject.argtypes = [wintypes.HDC, wintypes.HGDIOBJ]
gdi32.SelectObject.restype = wintypes.HGDIOBJ
gdi32.DeleteObject.argtypes = [wintypes.HGDIOBJ]
gdi32.DeleteObject.restype = wintypes.BOOL
gdi32.CreateDIBSection.argtypes = [wintypes.HDC, ctypes.c_void_p, wintypes.UINT,
                                   ctypes.POINTER(ctypes.c_void_p), wintypes.HANDLE,
                                   wintypes.DWORD]
gdi32.CreateDIBSection.restype = wintypes.HBITMAP


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [("biSize", wintypes.DWORD), ("biWidth", wintypes.LONG),
                ("biHeight", wintypes.LONG), ("biPlanes", wintypes.WORD),
                ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD),
                ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", wintypes.LONG),
                ("biYPelsPerMeter", wintypes.LONG), ("biClrUsed", wintypes.DWORD),
                ("biClrImportant", wintypes.DWORD)]


class BITMAPINFO(ctypes.Structure):
    _fields_ = [("bmiHeader", BITMAPINFOHEADER), ("bmiColors", wintypes.DWORD * 3)]


class BLENDFUNCTION(ctypes.Structure):
    _fields_ = [("BlendOp", ctypes.c_ubyte), ("BlendFlags", ctypes.c_ubyte),
                ("SourceConstantAlpha", ctypes.c_ubyte), ("AlphaFormat", ctypes.c_ubyte)]


class LayeredWindow:
    """Рисует PNG с альфой прямо в окно (сглаженные скругления и тень)."""

    GWL_EXSTYLE = -20
    WS_EX_LAYERED = 0x00080000
    WS_EX_TOOLWINDOW = 0x00000080
    SWP_NOSIZE = 0x0001
    SWP_NOMOVE = 0x0002
    SWP_NOZORDER = 0x0004
    SWP_NOACTIVATE = 0x0010
    SWP_FRAMECHANGED = 0x0020
    HWND_TOPMOST = -1
    ULW_ALPHA = 0x00000002
    AC_SRC_OVER = 0x00
    AC_SRC_ALPHA = 0x01
    BI_RGB = 0
    DIB_RGB_COLORS = 0

    def __init__(self, root):
        self.root = root
        self.hwnd = None
        self.hdc_screen = None
        self.hdc_mem = None
        self.hbmp = None
        self.size = None
        self.bits = None

    def attach(self):
        self.root.update_idletasks()
        self.root.update()
        wid = self.root.winfo_id()
        hwnd = user32.GetAncestor(wid, 2)          # GA_ROOT
        if not hwnd:
            hwnd = user32.GetParent(wid) or wid
        if hwnd == user32.GetDesktopWindow():
            hwnd = wid
        self.hwnd = hwnd
        ex = user32.GetWindowLongW(hwnd, self.GWL_EXSTYLE)
        user32.SetWindowLongW(hwnd, self.GWL_EXSTYLE,
                              ex | self.WS_EX_LAYERED | self.WS_EX_TOOLWINDOW)
        # без этого WS_EX_LAYERED не применяется к уже созданному окну
        user32.SetWindowPos(hwnd, None, 0, 0, 0, 0,
                            self.SWP_NOMOVE | self.SWP_NOSIZE |
                            self.SWP_NOZORDER | self.SWP_FRAMECHANGED)
        self.hdc_screen = user32.GetDC(None)
        self.hdc_mem = gdi32.CreateCompatibleDC(self.hdc_screen)
        return bool(self.hdc_screen and self.hdc_mem)

    def _create_dib(self, w, h):
        if self.hbmp:
            gdi32.SelectObject(self.hdc_mem, None)
            gdi32.DeleteObject(self.hbmp)
        bmi = BITMAPINFO()
        bmi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
        bmi.bmiHeader.biWidth = w
        bmi.bmiHeader.biHeight = -h
        bmi.bmiHeader.biPlanes = 1
        bmi.bmiHeader.biBitCount = 32
        bmi.bmiHeader.biCompression = self.BI_RGB
        self.bits = ctypes.c_void_p()
        self.hbmp = gdi32.CreateDIBSection(self.hdc_mem, ctypes.byref(bmi),
                                           self.DIB_RGB_COLORS,
                                           ctypes.byref(self.bits), None, 0)
        gdi32.SelectObject(self.hdc_mem, self.hbmp)
        self.size = (w, h)

    def set_image(self, pil_img):
        img = pil_img.convert("RGBA")
        w, h = img.size
        if self.size != (w, h) or self.hbmp is None:
            self._create_dib(w, h)
        # предумноженная альфа, порядок BGRA — как требует UpdateLayeredWindow
        pre = img.convert("RGBa")
        r, g, b, a = pre.split()
        buf = Image.merge("RGBA", (b, g, r, a)).tobytes()
        ctypes.memmove(self.bits, buf, w * h * 4)
        rect = wintypes.RECT()
        user32.GetWindowRect(self.hwnd, ctypes.byref(rect))
        pt_dst = wintypes.POINT(rect.left, rect.top)
        pt_src = wintypes.POINT(0, 0)
        size = wintypes.SIZE(w, h)
        bf = BLENDFUNCTION(self.AC_SRC_OVER, 0, 255, self.AC_SRC_ALPHA)
        ok = user32.UpdateLayeredWindow(
            self.hwnd, self.hdc_screen, ctypes.byref(pt_dst), ctypes.byref(size),
            self.hdc_mem, ctypes.byref(pt_src), 0, ctypes.byref(bf), self.ULW_ALPHA)
        self.keep_on_top()
        return bool(ok)

    def keep_on_top(self):
        """Не даём другим «поверх всех» окнам оказаться выше виджета."""
        if not self.hwnd:
            return
        user32.SetWindowPos(self.hwnd, self.HWND_TOPMOST, 0, 0, 0, 0,
                            self.SWP_NOMOVE | self.SWP_NOSIZE | self.SWP_NOACTIVATE)

    def destroy(self):
        try:
            if self.hbmp:
                gdi32.DeleteObject(self.hbmp)
            if self.hdc_mem:
                gdi32.DeleteDC(self.hdc_mem)
            if self.hdc_screen:
                user32.ReleaseDC(None, self.hdc_screen)
        except Exception:
            pass
        self.hbmp = self.hdc_mem = self.hdc_screen = None


# ===========================================================================
# 7. Приложение
# ===========================================================================

def enable_dpi_awareness():
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
        return
    except Exception:
        pass
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def system_scale():
    try:
        dpi = ctypes.windll.user32.GetDpiForSystem()
        return max(1.0, dpi / 96.0)
    except Exception:
        return 1.0


def clamp_scale(s):
    try:
        s = float(s)
    except (TypeError, ValueError):
        return USER_SCALE_DEFAULT
    if s != s:                                   # NaN
        return USER_SCALE_DEFAULT
    return max(USER_SCALE_MIN, min(USER_SCALE_MAX, round(s, 3)))


def load_prefs():
    """Позиция и пользовательский масштаб из widget_pos.json (позиция — обязательно)."""
    try:
        with open(POS_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        x, y = int(data["x"]), int(data["y"])
    except Exception:
        return None
    return x, y, clamp_scale(data.get("scale", USER_SCALE_DEFAULT))


def save_prefs(x, y, scale):
    try:
        with open(POS_FILE, "w", encoding="utf-8") as fh:
            json.dump({"x": int(x), "y": int(y), "scale": round(float(scale), 3)}, fh)
    except OSError:
        pass


def clamp_pos(x, y, win_w, win_h, sw, sh, spad):
    """Не даём карточке уехать за край экрана."""
    x = max(-spad, min(int(x), sw - win_w + spad))
    y = max(-spad, min(int(y), sh - win_h + spad))
    return x, y


class BatteryWorker(threading.Thread):
    """Фоновый поток: читает заряд, кладёт результаты в очередь."""

    def __init__(self, out_queue):
        super().__init__(daemon=True)
        self.q = out_queue
        self.stop_evt = threading.Event()
        self.wake_evt = threading.Event()
        self.reader = None
        self._last = None

    def refresh_now(self):
        self.wake_evt.set()

    def _connect(self):
        if not ensure_dll():
            return False
        path = find_control_path()
        if not path:
            return False
        try:
            reader = BatteryReader(path)
            reader.start()
        except Exception:
            return False
        self.reader = reader
        return True

    def _drop(self):
        if self.reader is not None:
            try:
                self.reader.stop()
            except Exception:
                pass
            self.reader = None

    def run(self):
        while not self.stop_evt.is_set():
            res = None
            if self.reader is None and not self._connect():
                self.q.put(("data", None))
            else:
                try:
                    res = self.reader.read(timeout=1.5)
                except Exception:
                    res = None
                if res is None:
                    self._drop()
                    self.q.put(("data", None))
                else:
                    self.q.put(("data", res))
            self.wake_evt.wait(POLL_INTERVAL_S)
            self.wake_evt.clear()
        self._drop()


def ss_for(scale):
    """Сглаживание при рендере: при крупном размере 2x достаточно."""
    return 3 if scale <= 1.6 else 2


def run_widget():
    if Image is None:
        run_simple_widget()
        return

    enable_dpi_awareness()
    dpi = system_scale()

    import tkinter as tk

    devices = [dict(icon="mouse.svg")]      # сюда потом добавится клавиатура
    states = [dict(level=None, charging=False, icon=d["icon"]) for d in devices]
    n = len(devices)
    cw, ch = card_size(n)

    prefs = load_prefs()
    user_scale = prefs[2] if prefs else USER_SCALE_DEFAULT

    def eff():
        """Итоговый масштаб: системный DPI × выбранный пользователем размер."""
        return dpi * user_scale

    win_w, win_h = widget_size_px(n, eff())
    spad = SHADOW_PAD * eff()

    root = tk.Tk()
    root.title("Заряд мыши")
    root.overrideredirect(True)
    root.attributes("-topmost", True)
    root.configure(bg="#211e21")

    sw = root.winfo_screenwidth()
    sh = root.winfo_screenheight()
    margin = 26 * eff()
    pos_x = int(round(sw - margin - spad - cw * eff()))
    pos_y = int(round(margin - spad))
    if prefs:
        pos_x, pos_y = clamp_pos(prefs[0], prefs[1], win_w, win_h, sw, sh,
                                 int(round(spad)))
    root.geometry("%dx%d+%d+%d" % (win_w, win_h, pos_x, pos_y))
    root.update_idletasks()

    lw = LayeredWindow(root)
    layered_ok = lw.attach()

    ui = {"grip_hot": False}

    def redraw():
        img = render_widget(states, eff(), ss=ss_for(eff()), grip=ui["grip_hot"])
        if layered_ok:
            lw.set_image(img)
        else:
            # запасной вариант без попиксельной прозрачности
            from PIL import ImageTk
            photo = ImageTk.PhotoImage(img)
            lbl = getattr(redraw, "lbl", None)
            if lbl is None:
                lbl = tk.Label(root, bd=0, highlightthickness=0)
                lbl.pack()
                redraw.lbl = lbl
            lbl.configure(image=photo)
            redraw.photo = photo

    def set_scale(new_user, anchor="center"):
        """Изменить размер виджета, сохранив его позицию (anchor: card | center)."""
        nonlocal user_scale, win_w, win_h, spad
        new_user = clamp_scale(new_user)
        if abs(new_user - user_scale) < 1e-4:
            return False
        old_eff = eff()
        old_spad = spad
        card_x = root.winfo_x() + old_spad
        card_y = root.winfo_y() + old_spad
        if anchor == "center":
            ax = card_x + cw * old_eff / 2.0
            ay = card_y + ch * old_eff / 2.0
        else:
            ax, ay = card_x, card_y
        user_scale = new_user
        win_w, win_h = widget_size_px(n, eff())
        spad = SHADOW_PAD * eff()
        if anchor == "center":
            x = ax - cw * eff() / 2.0 - spad
            y = ay - ch * eff() / 2.0 - spad
        else:
            x = ax - spad
            y = ay - spad
        x, y = clamp_pos(int(round(x)), int(round(y)), win_w, win_h, sw, sh,
                         int(round(spad)))
        root.geometry("%dx%d+%d+%d" % (win_w, win_h, x, y))
        root.update_idletasks()
        redraw()
        save_prefs(x, y, user_scale)
        return True

    q = queue.Queue()
    worker = BatteryWorker(q)

    def apply_item(item):
        kind, payload = item
        if kind != "data":
            return
        st = states[0]
        if payload:
            st["level"], st["charging"], st["voltage"] = payload
        else:
            st["level"] = None
            st["charging"] = False
        redraw()

    def tick():
        try:
            while True:
                item = q.get_nowait()
                apply_item(item)
        except queue.Empty:
            pass
        root.after(200, tick)

    drag = {"dx": 0, "dy": 0, "on": False}
    grip = {"on": False, "x0": 0, "y0": 0}

    def in_grip(e):
        g = GRIP_LOGICAL * eff()
        return (e.x >= win_w - spad - g) and (e.y >= win_h - spad - g)

    def set_cursor(hot):
        if ui["grip_hot"] == hot:
            return
        ui["grip_hot"] = hot
        try:
            root.configure(cursor="size_nw_se" if hot else "")
        except tk.TclError:
            try:
                root.configure(cursor="sizing" if hot else "")
            except tk.TclError:
                pass
        redraw()

    def scale_from_px(width_px):
        """Масштаб по желаемой ширине карточки (шаг 5 %)."""
        raw = width_px / max(1.0, cw * dpi)
        return clamp_scale(round(raw / 0.05) * 0.05)

    def on_press(e):
        if e.num == 1 and in_grip(e):
            grip["on"] = True
            drag["on"] = False
            grip["x0"] = root.winfo_x() + spad
            grip["y0"] = root.winfo_y() + spad
            return
        drag["on"] = True
        drag["dx"] = e.x_root - root.winfo_x()
        drag["dy"] = e.y_root - root.winfo_y()

    def on_drag(e):
        if grip["on"]:
            set_scale(scale_from_px(e.x_root - grip["x0"]), anchor="card")
            return
        if not drag["on"]:
            return
        root.geometry("+%d+%d" % (e.x_root - drag["dx"], e.y_root - drag["dy"]))

    def on_release(e):
        if grip["on"]:
            grip["on"] = False
            save_prefs(root.winfo_x(), root.winfo_y(), user_scale)
            return
        if drag["on"]:
            drag["on"] = False
            x, y = clamp_pos(root.winfo_x(), root.winfo_y(), win_w, win_h,
                             root.winfo_screenwidth(), root.winfo_screenheight(),
                             int(round(spad)))
            root.geometry("+%d+%d" % (x, y))
            save_prefs(x, y, user_scale)
            if layered_ok:
                redraw()

    def on_motion(e):
        set_cursor(in_grip(e))

    def on_wheel(e):
        # Ctrl + колесо — размер виджета
        if not (e.state & 0x0004):
            return
        step = USER_SCALE_STEP if e.delta > 0 else -USER_SCALE_STEP
        set_scale(round(user_scale + step, 2))

    def keep_on_top():
        if layered_ok:
            lw.keep_on_top()
        else:
            root.attributes("-topmost", True)
        root.after(3000, keep_on_top)

    def build_menu():
        menu = tk.Menu(root, tearoff=0)
        menu.add_command(label="Размер: %d%%" % int(round(user_scale * 100)),
                         state="disabled")
        menu.add_command(label="Крупнее  (Ctrl + колесо вверх)",
                         command=lambda: set_scale(round(user_scale + USER_SCALE_STEP, 2)))
        menu.add_command(label="Мельче  (Ctrl + колесо вниз)",
                         command=lambda: set_scale(round(user_scale - USER_SCALE_STEP, 2)))
        menu.add_command(label="Обычный размер (100%)",
                         command=lambda: set_scale(USER_SCALE_DEFAULT))
        menu.add_separator()
        menu.add_command(label="Обновить сейчас", command=worker.refresh_now)
        menu.add_separator()
        menu.add_command(label="Выход", command=on_close)
        return menu

    def on_menu(e):
        menu = build_menu()
        try:
            menu.tk_popup(e.x_root, e.y_root)
        finally:
            menu.grab_release()

    def on_close():
        worker.stop_evt.set()
        worker.wake_evt.set()
        lw.destroy()
        root.destroy()

    root.bind("<Button-1>", on_press)
    root.bind("<B1-Motion>", on_drag)
    root.bind("<ButtonRelease-1>", on_release)
    root.bind("<Button-3>", on_menu)
    root.bind("<Motion>", on_motion)
    root.bind("<Leave>", lambda e: set_cursor(False))
    root.bind("<MouseWheel>", on_wheel)

    redraw()
    worker.start()
    root.after(200, tick)
    root.after(3000, keep_on_top)
    try:
        root.mainloop()
    finally:
        worker.stop_evt.set()
        worker.wake_evt.set()
        lw.destroy()


# ---------------------------------------------------------------------------
# Запасной виджет без Pillow (простой текст)
# ---------------------------------------------------------------------------

def run_simple_widget():
    import tkinter as tk

    enable_dpi_awareness()
    root = tk.Tk()
    root.title("Заряд мыши")
    root.overrideredirect(True)
    root.attributes("-topmost", True)
    BG = "#17181c"
    root.configure(bg=BG)

    pct = tk.Label(root, text="--%", font=("Segoe UI", 24, "bold"), bg=BG, fg="#71717a")
    pct.pack(padx=18, pady=(10, 2))
    sub = tk.Label(root, text="мышь", font=("Segoe UI", 9), bg=BG, fg="#a1a1aa")
    sub.pack(padx=18, pady=(0, 10))

    state = {"reader": None}

    def poll():
        if state["reader"] is None:
            try:
                path = find_control_path()
                if path:
                    r = BatteryReader(path)
                    r.start()
                    state["reader"] = r
            except Exception:
                state["reader"] = None
        res = None
        if state["reader"] is not None:
            try:
                res = state["reader"].read(timeout=1.5)
            except Exception:
                res = None
        if res:
            level, charging, volt = res
            color = "#60a5fa" if charging else ("#4ade80" if level >= 50 else ("#fbbf24" if level >= 20 else "#f87171"))
            pct.config(text="%d%%" % level, fg=color)
            sub.config(text=("зарядка · " if charging else "") + "%.2f В" % (volt / 1000.0))
        else:
            pct.config(text="--%", fg="#71717a")
            sub.config(text="нет данных")
        root.after(20000, poll)

    def on_close():
        if state["reader"] is not None:
            state["reader"].stop()
        root.destroy()

    drag = {"dx": 0, "dy": 0}

    def on_press(e):
        drag["dx"] = e.x_root - root.winfo_x()
        drag["dy"] = e.y_root - root.winfo_y()

    def on_drag(e):
        root.geometry("+%d+%d" % (e.x_root - drag["dx"], e.y_root - drag["dy"]))

    menu = tk.Menu(root, tearoff=0)
    menu.add_command(label="Обновить сейчас", command=poll)
    menu.add_separator()
    menu.add_command(label="Выход", command=on_close)

    def on_menu(e):
        try:
            menu.tk_popup(e.x_root, e.y_root)
        finally:
            menu.grab_release()

    for w in (root, pct, sub):
        w.bind("<Button-1>", on_press)
        w.bind("<B1-Motion>", on_drag)
        w.bind("<Button-3>", on_menu)

    root.update_idletasks()
    sw = root.winfo_screenwidth()
    root.geometry("+%d+%d" % (sw - root.winfo_reqwidth() - 24, 24))
    poll()
    root.mainloop()


# ===========================================================================
# 8. Точка входа
# ===========================================================================

def save_preview(path, level=73, charging=False, scale=1.0):
    if Image is None:
        raise RuntimeError("Pillow не установлен")
    st = [dict(level=level, charging=charging, icon="mouse.svg")]
    img = render_widget(st, scale, ss=4 if scale <= 1.6 else 3)
    bg = Image.new("RGBA", img.size, (18, 18, 20, 255))
    bg.alpha_composite(img)
    bg.convert("RGB").save(path)
    return path


def main():
    args = sys.argv[1:]

    if "--preview" in args:
        i = args.index("--preview")
        out = args[i + 1] if i + 1 < len(args) and not args[i + 1].startswith("--") else "widget_preview.png"
        level = 73
        if "--level" in args:
            try:
                level = int(args[args.index("--level") + 1])
            except Exception:
                level = 73
        scale = 1.0
        if "--scale" in args:
            try:
                scale = clamp_scale(args[args.index("--scale") + 1])
            except Exception:
                scale = 1.0
        charging = "--charging" in args
        p = os.path.join(BASE_DIR, out) if not os.path.isabs(out) else out
        print(save_preview(p, level=level, charging=charging, scale=scale))
        return

    if "--once" in args:
        if not ensure_dll():
            print("Не удалось найти/извлечь HIDUsb.dll.", file=sys.stderr)
            sys.exit(1)
        path = find_control_path()
        if not path:
            print("Донгл мыши (2.4G Wireless Receiver) не найден.", file=sys.stderr)
            sys.exit(1)
        reader = BatteryReader(path)
        reader.start()
        try:
            res = reader.read(timeout=2.0)
            if res:
                print("level=%d%% charging=%d voltage=%dmV" % (res[0], res[1], res[2]))
            else:
                print("нет данных")
        finally:
            reader.stop()
        return

    if not ensure_dll():
        print("Не удалось найти/извлечь HIDUsb.dll.", file=sys.stderr)
    run_widget()


if __name__ == "__main__":
    main()
