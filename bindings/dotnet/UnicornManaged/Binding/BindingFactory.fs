namespace UnicornManaged.Binding

open System

module BindingFactory =
    let mutable _instance = NativeBinding.instance

    let setDefaultBinding(binding: IBinding) =
        _instance <- binding
    
    let getDefault() =
        _instance

