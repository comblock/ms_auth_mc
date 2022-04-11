use {
	ms_auth_mc::*,
	reqwest::blocking::Client
};

#[test]
fn auth() {
	let client = Client::new();
	let device_code = DeviceCode::new("389b1b32-b5d5-43b2-bddc-84ce938d6737", None, &client).unwrap();
	match &device_code.inner {
		None => (),
		Some(inner) => {
			println!("{}", inner.message)
		}
	}
	let auth = device_code.authenticate(&client).unwrap();
	println!("{}", auth.token);
}