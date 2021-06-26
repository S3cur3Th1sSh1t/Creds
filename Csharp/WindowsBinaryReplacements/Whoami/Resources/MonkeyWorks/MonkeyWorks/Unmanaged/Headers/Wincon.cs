using System;

namespace MonkeyWorks.Unmanaged.Headers
{ 
    class Wincon
    {
        [Flags]
        public enum CtrlType : uint
        {
            CTRL_C_EVENT = 0,
            CTRL_BREAK_EVENT = 1,
            CTRL_CLOSE_EVENT = 2,
            CTRL_LOGOFF_EVENT = 5,
            CTRL_SHUTDOWN_EVENT = 6
        }
    }
}