/*
* JS Policy to grant access to user for DeleteRole to resources with attribute Status=Closed and Condition=Sold and TypeOfDocument=Dataset
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
if (idtValue !== undefined && idtValue === 'user6') {

    // read Resource Attr
    var permission = $evaluation.getPermission();
    var resource = permission.getResource();
    var attributes = resource.getAttributes();

    var attr = 'Status';
    var attr1 = 'Condition';
    var attr2 = 'Dataset';
    if (attributes[attr] !== undefined && attributes[attr][0] === 'Closed' && attributes[attr1] !== undefined && attributes[attr1][0] === 'Sold' && attributes[attr2] !== undefined && attributes[attr2][0] === 'Dataset') {
        $evaluation.grant();
    }
}

