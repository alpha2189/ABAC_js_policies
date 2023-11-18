/*
* PISTIS JS Policy to grant access for user CreateRole to resources with attribute Condition=NotSold and Type=Datastream
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
if (idtValue !== undefined && idtValue === 'user1') {

    // read Resource Attr
    var permission = $evaluation.getPermission();
    var resource = permission.getResource();
    var attributes = resource.getAttributes();

    var attr = 'Condition';
    var attr1 = 'Type';

    if (attributes[attr] !== undefined && attributes[attr][0] === 'NotSold' && attributes[attr1] !== undefined && attributes[attr1][0] === 'Datastream') {
        $evaluation.grant();
    }
}
