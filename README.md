# ms_auth_mc
This library is for logging into a minecraft account using the microsoft oauth2 device flow: https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code
## Example
```
const CID: &str = "client id from an azure application"
fn main() {
let client = &reqwest::blocking::Client::new();
   let device_code = ms_auth_mc::DeviceCode::new(CID, None, client).unwrap();
   if !device_code.cached {
     println!("{}", device_code.message)
}
let mca = device_code.authenticate(client).unwrap(); // Never use unwrap here, it's used in this example for simplicity
println!("{:?}", mca)
```
You can create your own cid by making an azure application.
