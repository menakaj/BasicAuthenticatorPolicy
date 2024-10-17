import ballerina/http;
import choreo/mediation;
import ballerina/lang.array;

// A mediation policy package consists of 1-3 functions, each corresponding to one of the 3 possible request/response
// flows:
// - In-flow function is applied to a request coming in to a resource in the proxy
// - Out-flow function is applied to the response received from the upstream server before forwarding it to the client
// - Fault-flow function is applied if an error occurs in any of the above 2 flows and the control flow is handed over
//   to the error handling flow
//
// A policy can contain any combination of the above 3 flows. Therefore one can get rid of up to any 2 of the following
// functions. The function names are irrelevant. Therefore one can name them as they see fit.

// The first 2 parameters are required. After the first 2 parameters, one can add arbitrary number of parameters of
// the following types: int, string, float, boolean, decimal. However, all policy functions should have exactly the same
// number and types of these arbitrary parameters.

@mediation:RequestFlow
public function authenticate(mediation:Context ctx, http:Request req, string username, string password) 
                                returns http:Response|false|error|() {
    
    string|http:HeaderNotFoundError header = req.getHeader("Authorization");
    if header is http:HeaderNotFoundError {
        http:Response unauthenticatedRes = new;
        unauthenticatedRes.statusCode = http:STATUS_UNAUTHORIZED;
        unauthenticatedRes.setTextPayload("Authorization header not found");
        return unauthenticatedRes;
    }

    if !header.includes("Basic ") {
        http:Response unauthenticatedRes = new;
        unauthenticatedRes.statusCode = http:STATUS_UNAUTHORIZED;
        unauthenticatedRes.setTextPayload("Invalid basic auth header format. Missing 'Basic'");
        return unauthenticatedRes;
    }
    
    string:RegExp del = re ` `;


    string[] headerParts = del.split(header);

    if headerParts.length() < 2 {
        http:Response unauthenticatedRes = new;
        unauthenticatedRes.statusCode = http:STATUS_UNAUTHORIZED;
        unauthenticatedRes.setTextPayload("Invalid basic auth header format");
        return unauthenticatedRes;
    }
    string credentials = check getDecodedBase64String(headerParts[1]);
    string:RegExp colon = re `:`;
    string[] userNamePass = colon.split(credentials);

    if userNamePass.length() < 2 {
         http:Response unauthenticatedRes = new;
        unauthenticatedRes.statusCode = http:STATUS_UNAUTHORIZED;
        unauthenticatedRes.setTextPayload("Invalid credentials. Missing username or password");
        return unauthenticatedRes;
    }

    if userNamePass[0] == username && userNamePass[1] == password {
        req.removeHeader("Authorization");
        return;
    }

    http:Response unauthenticatedRes = new;
    unauthenticatedRes.statusCode = http:STATUS_UNAUTHORIZED;
    unauthenticatedRes.setTextPayload("Invalid credentials");
    return unauthenticatedRes;
}


function getDecodedBase64String(string base64string) returns string|error {
    byte[]|error fromBase64Bytes = array:fromBase64(base64string);

    if fromBase64Bytes is error {
        return error(string `Error while decoding base64 string: ${fromBase64Bytes.message()}`);
    }

    string|error decodedString = string:fromBytes(fromBase64Bytes);

    if decodedString is error {
        return error(string `Error while converting decoded string from bytes: ${decodedString.message()}`);
    }
    return decodedString;
}