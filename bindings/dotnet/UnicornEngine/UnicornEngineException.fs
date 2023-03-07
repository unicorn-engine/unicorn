namespace UnicornManaged

open System

type UnicornEngineException(errNo: Int32, msg: String) =
    inherit ApplicationException(msg)

    member this.ErrorNo = errNo

