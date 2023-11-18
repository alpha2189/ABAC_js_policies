/*
* PISTIS JS Policy to grant access for user TradeRole to resources with attribute Status=Open and Condition=NotSold and File=.sql
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
if (idtValue !== undefined) {

    // read Resource Attr
    var permission = $evaluation.getPermission();
    var resource = permission.getResource();
    var attributes = resource.getAttributes();

    var attr = 'Status';
    var attr1 = 'Condition';
    var attr2 = 'File';
    if (attributes[attr] !== undefined && attributes[attr][0] === 'Open' && attributes[attr1] !== undefined && attributes[attr1][0] === 'NotSold' && attributes[attr2] !== undefined && attributes[attr2][0] === '.sql') {
        $evaluation.grant();
    }
}