/****
 * 
 * resource: org:ruv
 * role: role:org:ruv:reader
 * https://www.keycloak.org/docs-api/17.0/javadocs/org/keycloak/authorization/common/KeycloakIdentity.html
 */

if (!String.prototype.includes) {
  String.prototype.includes = function (search, start) {
    'use strict';
    if (typeof start !== 'number') {
      start = 0;
    }

    if (start + search.length > this.length) {
      return false;
    } else {
      return this.indexOf(search, start) !== -1;
    }
  };
}

var context = $evaluation.getContext();
var identity = context.getIdentity();


var permission = $evaluation.permission; // https://www.keycloak.org/docs-api/17.0/javadocs/org/keycloak/authorization/permission/ResourcePermission.html
print("$evaluation: ", $evaluation)
var resource = permission.resource;
print("-------- Authz Policy: HasRoleOrgReader ------------");


var rname = String(resource.name);
print("rname includes ':org': ", rname.includes("org:"));
print("resource name: ", rname);
print("resource scope: ", resource.scopes);
print("--------------------");

if (rname.includes(":team")) {
  rname = rname.split(0, 3);
}

// identity.hasRealmRole("role:" + resource.name + ":reader")
if (rname.includes("org:") && identity.hasRealmRole("role:" + rname + ":reader")) {
  $evaluation.grant();
}