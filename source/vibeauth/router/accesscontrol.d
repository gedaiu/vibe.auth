module vibeauth.router.accesscontrol;


import vibe.http.router;

void setAccessControl(ref HTTPServerResponse res) {
	if("Access-Control-Allow-Origin" !in res.headers) {
		res.headers["Access-Control-Allow-Origin"] = "*";
	} else {
		res.headers["Access-Control-Allow-Origin"] = ", *";
	}

	if("Access-Control-Allow-Headers" !in res.headers) {
		res.headers["Access-Control-Allow-Headers"] = "Authorization";
	} else {
		res.headers["Access-Control-Allow-Headers"] = ", Authorization";
	}
}
