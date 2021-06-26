using System;
using System.Runtime.InteropServices;

using WORD = System.UInt16;
using DWORD = System.UInt32;
using QWORD = System.UInt64;

using USHORT = System.UInt16;
using ULONG = System.UInt32;

using LPCTSTR = System.String;
using LPWSTR = System.Text.StringBuilder;

using PVOID = System.IntPtr;
using LPVOID = System.IntPtr;
using DWORD_PTR = System.IntPtr;

using WCHAR = System.Char;

namespace MonkeyWorks.Unmanaged.Headers
{
    public class FltUserStructures
    {
        public enum _FILTER_INFORMATION_CLASS
        {
            FilterFullInformation,
            FilterAggregateBasicInformation,
            FilterAggregateStandardInformation
        }
        //FILTER_INFORMATION_CLASS, *PFILTER_INFORMATION_CLASS;

        [StructLayout(LayoutKind.Sequential)]
        public struct _FILTER_AGGREGATE_BASIC_INFORMATION
        {
            public ULONG NextEntryOffset;
            public ULONG Flags;
            public ULONG FrameID;
            public ULONG NumberOfInstances;
            public USHORT FilterNameLength;
            public USHORT FilterNameBufferOffset;
            public USHORT FilterAltitudeLength;
            public USHORT FilterAltitudeBufferOffset;
        }
        //FILTER_AGGREGATE_BASIC_INFORMATION, *PFILTER_AGGREGATE_BASIC_INFORMATION;

        [StructLayout(LayoutKind.Sequential)]
        public struct _FILTER_AGGREGATE_STANDARD_INFORMATION
        {
            public ULONG NextEntryOffset;
            public ULONG Flags;
            public ULONG FrameID;
            public ULONG NumberOfInstances;
            public USHORT FilterNameLength;
            public USHORT FilterNameBufferOffset;
            public USHORT FilterAltitudeLength;
            public USHORT FilterAltitudeBufferOffset;
        }
        // FILTER_AGGREGATE_STANDARD_INFORMATION, * PFILTER_AGGREGATE_STANDARD_INFORMATION;

        [StructLayout(LayoutKind.Sequential)]
        public struct _FILTER_FULL_INFORMATION
        {
            public ULONG NextEntryOffset;
            public ULONG FrameID;
            public ULONG NumberOfInstances;
            public USHORT FilterNameLength;
            public WCHAR[] FilterNameBuffer;
        }
        //FILTER_FULL_INFORMATION, *PFILTER_FULL_INFORMATION;

        [Flags]
        public enum _FLT_FILESYSTEM_TYPE
        {
            FLT_FSTYPE_UNKNOWN,
            FLT_FSTYPE_RAW,
            FLT_FSTYPE_NTFS,
            FLT_FSTYPE_FAT,
            FLT_FSTYPE_CDFS,
            FLT_FSTYPE_UDFS,
            FLT_FSTYPE_LANMAN,
            FLT_FSTYPE_WEBDAV,
            FLT_FSTYPE_RDPDR,
            FLT_FSTYPE_NFS,
            FLT_FSTYPE_MS_NETWARE,
            FLT_FSTYPE_NETWARE,
            FLT_FSTYPE_BSUDF,
            FLT_FSTYPE_MUP,
            FLT_FSTYPE_RSFX,
            FLT_FSTYPE_ROXIO_UDF1,
            FLT_FSTYPE_ROXIO_UDF2,
            FLT_FSTYPE_ROXIO_UDF3,
            FLT_FSTYPE_TACIT,
            FLT_FSTYPE_FS_REC,
            FLT_FSTYPE_INCD,
            FLT_FSTYPE_INCD_FAT,
            FLT_FSTYPE_EXFAT,
            FLT_FSTYPE_PSFS,
            FLT_FSTYPE_GPFS,
            FLT_FSTYPE_NPFS,
            FLT_FSTYPE_MSFS,
            FLT_FSTYPE_CSVFS,
            FLT_FSTYPE_REFS,
            FLT_FSTYPE_OPENAFS
        }
        //FLT_FILESYSTEM_TYPE, *PFLT_FILESYSTEM_TYPE;

        [StructLayout(LayoutKind.Sequential)]
        public struct _INSTANCE_AGGREGATE_STANDARD_INFORMATION
        {
            public ULONG NextEntryOffset;
            public ULONG Flags;
            public ULONG FrameID;
            public _FLT_FILESYSTEM_TYPE VolumeFileSystemType;
            public USHORT InstanceNameLength;
            public USHORT InstanceNameBufferOffset;
            public USHORT AltitudeLength;
            public USHORT AltitudeBufferOffset;
            public USHORT VolumeNameLength;
            public USHORT VolumeNameBufferOffset;
            public USHORT FilterNameLength;
            public USHORT FilterNameBufferOffset;
            public ULONG SupportedFeatures;
        }
        //INSTANCE_AGGREGATE_STANDARD_INFORMATION, * PINSTANCE_AGGREGATE_STANDARD_INFORMATION;

        [StructLayout(LayoutKind.Sequential)]
        public struct _INSTANCE_BASIC_INFORMATION
        {
            public ULONG NextEntryOffset;
            public USHORT InstanceNameLength;
            public USHORT InstanceNameBufferOffset;
        }
        //INSTANCE_BASIC_INFORMATION, PINSTANCE_BASIC_INFORMATION;

        [Flags]
        public enum _INSTANCE_INFORMATION_CLASS
        {

            InstanceBasicInformation,
            InstancePartialInformation,
            InstanceFullInformation,
            InstanceAggregateStandardInformation

        }
        //INSTANCE_INFORMATION_CLASS, *PINSTANCE_INFORMATION_CLASS;

        [StructLayout(LayoutKind.Sequential)]
        public struct _INSTANCE_FULL_INFORMATION
        {
            public ULONG NextEntryOffset;
            public USHORT InstanceNameLength;
            public USHORT InstanceNameBufferOffset;
            public USHORT AltitudeLength;
            public USHORT AltitudeBufferOffset;
            public USHORT VolumeNameLength;
            public USHORT VolumeNameBufferOffset;
            public USHORT FilterNameLength;
            public USHORT FilterNameBufferOffset;
        }
        //INSTANCE_FULL_INFORMATION, PINSTANCE_FULL_INFORMATION;

        [StructLayout(LayoutKind.Sequential)]
        public struct _INSTANCE_PARTIAL_INFORMATION
        {
            public ULONG NextEntryOffset;
            public USHORT InstanceNameLength;
            public USHORT InstanceNameBufferOffset;
            public USHORT AltitudeLength;
            public USHORT AltitudeBufferOffset;
        }
        //INSTANCE_PARTIAL_INFORMATION, PINSTANCE_PARTIAL_INFORMATION;
    }
}
