# ms_auth_mc
This library is for logging into a minecraft account by using the microsoft oauth2 device flow: https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code
## Example
```rs
use {ms_auth_mc::*, reqwest::blocking::Client};

let client = Client::new();
let device_code =
    DeviceCode::new("389b1b32-b5d5-43b2-bddc-84ce938d6737"/* You would ideally replace this with your own CID*/, None, &client).unwrap();
 
if let Some(inner) = &device_code.inner {
   println!("{}", inner.message);
}
 
let auth = device_code.authenticate(&client).unwrap();
println!("{}", auth.token);
```
You can create your own cid by making an azure application.
