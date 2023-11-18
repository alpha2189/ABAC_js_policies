/*
* JS Policy to grant access for UpdateRole to resources with attribute Status=Open and Type=Dataset
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
if (idtValue !== undefined && idtValue === 'user4') {

    // read Resource Attr
    var permission = $evaluation.getPermission();
    var resource = permission.getResource();
    var attributes = resource.getAttributes();

    var attr = 'Status';
    var attr1 = 'Type';

    if (attributes[attr] !== undefined && attributes[attr][0] === 'Open' && attributes[attr1] !== undefined && attributes[attr1][0] === 'Dataset') {
        $evaluation.grant();
    }
}
