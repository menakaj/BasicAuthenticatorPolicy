import ballerina/test;
import ballerina/http;
import choreo/mediation;

@test:Config{}
function testBasicAuthSuccess() {
    http:Request req = new;
    string creds = "YWRtaW46YWRtaW4K=";
    req.setHeader("Authorization", string `Basic ${creds}`);

    mediation:Context ctx = createContext("POST", "/test/auth");

    error|()|http:Response|false policyNameInResult = authenticate(ctx, req, "admin", "admin");

    test:assertTrue(policyNameInResult is ());
}


@test:Config{}
function testBasicAuthInvalidHeaderName() {
    http:Request req = new;
    string creds = "admin:abcdef".toBytes().toBase64();
    req.setHeader("Authorizationxx", string `Basic ${creds}`);

    mediation:Context ctx = createContext("POST", "/test/auth");

    error|()|http:Response|false policyNameInResult = authenticate(ctx, req, "admin", "abcdef");

    test:assertTrue(policyNameInResult is http:Response);
    if policyNameInResult is http:Response {
        test:assertEquals(policyNameInResult.statusCode, http:STATUS_UNAUTHORIZED);
    }
}


@test:Config{}
function testBasicAuthInvalidFormat() {
    http:Request req = new;
    string creds = "admin:abcdef".toBytes().toBase64();
    req.setHeader("Authorization", string `Basi${creds}`);

    mediation:Context ctx = createContext("POST", "/test/auth");

    error|()|http:Response|false policyNameInResult = authenticate(ctx, req, "admin", "abcdef");

    test:assertTrue(policyNameInResult is http:Response);
    if policyNameInResult is http:Response {
        test:assertEquals(policyNameInResult.statusCode, http:STATUS_UNAUTHORIZED);
    }
}


function createContext(string httpMethod, string resPath) returns mediation:Context {
   mediation:ResourcePath originalPath = checkpanic mediation:createImmutableResourcePath(resPath);
   mediation:Context originalCtx =
               mediation:createImmutableMediationContext(httpMethod, originalPath.pathSegments(), {}, {});
   mediation:ResourcePath mutableResPath = checkpanic mediation:createMutableResourcePath(resPath);
   return mediation:createMutableMediationContext(originalCtx, mutableResPath.pathSegments(), {}, {});
}