/*
* TestJSPolicy1 to grant access for user = ReadRole to resources with attribute status=Open
*
 */


/*
* Realm
 */
var realm = $evaluation.getRealm();

/*
* Context
 */
var context = $evaluation.context;
var ctxAttributes = context.getAttributes();
var identity = context.identity;
var identityAttributes = identity.getAttributes();

var idtAttr = 'preferred_username';
var idtValue = identityAttributes.getValue(idtAttr) !== undefined ? identityAttributes.getValue(idtAttr).asString(0) : undefined;

$evaluation.deny();
if (idtValue !== undefined && idtValue === 'user3') {

    // read Resource Attr
    var permission = $evaluation.getPermission();
    var resource = permission.getResource();
    var attributes = resource.getAttributes();

    var attr = 'Status';


    if (attributes[attr] !== undefined && attributes[attr][0] === 'Open') {
        $evaluation.grant();
    }
}

