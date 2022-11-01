namespace UnicornManaged.Binding


module BindingFactory =
    let mutable _instance = NativeBinding.instance

    let setDefaultBinding(binding: IBinding) =
        _instance <- binding

    let getDefault() =
        _instance
