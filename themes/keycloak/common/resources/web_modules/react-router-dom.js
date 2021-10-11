import"./common/_commonjsHelpers-87462ed4.js";import{p as t}from"./common/index-31d0caab.js";import e from"./react.js";var n=function(){},o=function(){},r=function(t,e,n,o,r,i,a,c){if(!t){var s;if(void 0===e)s=new Error("Minified exception occurred; use the non-minified dev environment for the full error message and additional helpful warnings.");else{var u=[n,o,r,i,a,c],p=0;(s=new Error(e.replace(/%s/g,(function(){return u[p++]})))).name="Invariant Violation"}throw s.framesToPop=1,s}};function i(t){return"/"===t.charAt(0)}function a(t,e){for(var n=e,o=n+1,r=t.length;o<r;n+=1,o+=1)t[n]=t[o];t.pop()}var c="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(t){return typeof t}:function(t){return t&&"function"==typeof Symbol&&t.constructor===Symbol&&t!==Symbol.prototype?"symbol":typeof t};var s=function(t){return"/"===t.charAt(0)?t:"/"+t},u=function(t){return"/"===t.charAt(0)?t.substr(1):t},p=function(t,e){return new RegExp("^"+e+"(\\/|\\?|#|$)","i").test(t)},l=function(t,e){return p(t,e)?t.substr(e.length):t},f=function(t){return"/"===t.charAt(t.length-1)?t.slice(0,-1):t},h=function(t){var e=t.pathname,n=t.search,o=t.hash,r=e||"/";return n&&"?"!==n&&(r+="?"===n.charAt(0)?n:"?"+n),o&&"#"!==o&&(r+="#"===o.charAt(0)?o:"#"+o),r},y=Object.assign||function(t){for(var e=1;e<arguments.length;e++){var n=arguments[e];for(var o in n)Object.prototype.hasOwnProperty.call(n,o)&&(t[o]=n[o])}return t},d=function(t,e,n,o){var r=void 0;"string"==typeof t?(r=function(t){var e=t||"/",n="",o="",r=e.indexOf("#");-1!==r&&(o=e.substr(r),e=e.substr(0,r));var i=e.indexOf("?");return-1!==i&&(n=e.substr(i),e=e.substr(0,i)),{pathname:e,search:"?"===n?"":n,hash:"#"===o?"":o}}(t)).state=e:(void 0===(r=y({},t)).pathname&&(r.pathname=""),r.search?"?"!==r.search.charAt(0)&&(r.search="?"+r.search):r.search="",r.hash?"#"!==r.hash.charAt(0)&&(r.hash="#"+r.hash):r.hash="",void 0!==e&&void 0===r.state&&(r.state=e));try{r.pathname=decodeURI(r.pathname)}catch(t){throw t instanceof URIError?new URIError('Pathname "'+r.pathname+'" could not be decoded. This is likely caused by an invalid percent-encoding.'):t}return n&&(r.key=n),o?r.pathname?"/"!==r.pathname.charAt(0)&&(r.pathname=function(t){var e=arguments.length>1&&void 0!==arguments[1]?arguments[1]:"",n=t&&t.split("/")||[],o=e&&e.split("/")||[],r=t&&i(t),c=e&&i(e),s=r||c;if(t&&i(t)?o=n:n.length&&(o.pop(),o=o.concat(n)),!o.length)return"/";var u=void 0;if(o.length){var p=o[o.length-1];u="."===p||".."===p||""===p}else u=!1;for(var l=0,f=o.length;f>=0;f--){var h=o[f];"."===h?a(o,f):".."===h?(a(o,f),l++):l&&(a(o,f),l--)}if(!s)for(;l--;l)o.unshift("..");!s||""===o[0]||o[0]&&i(o[0])||o.unshift("");var y=o.join("/");return u&&"/"!==y.substr(-1)&&(y+="/"),y}(r.pathname,o.pathname)):r.pathname=o.pathname:r.pathname||(r.pathname="/"),r},v=function(t,e){return t.pathname===e.pathname&&t.search===e.search&&t.hash===e.hash&&t.key===e.key&&function t(e,n){if(e===n)return!0;if(null==e||null==n)return!1;if(Array.isArray(e))return Array.isArray(n)&&e.length===n.length&&e.every((function(e,o){return t(e,n[o])}));var o=void 0===e?"undefined":c(e);if(o!==(void 0===n?"undefined":c(n)))return!1;if("object"===o){var r=e.valueOf(),i=n.valueOf();if(r!==e||i!==n)return t(r,i);var a=Object.keys(e),s=Object.keys(n);return a.length===s.length&&a.every((function(o){return t(e[o],n[o])}))}return!1}(t.state,e.state)},m=function(){var t=null,e=[];return{setPrompt:function(e){return t=e,function(){t===e&&(t=null)}},confirmTransitionTo:function(e,n,o,r){if(null!=t){var i="function"==typeof t?t(e,n):t;"string"==typeof i?"function"==typeof o?o(i,r):r(!0):r(!1!==i)}else r(!0)},appendListener:function(t){var n=!0,o=function(){n&&t.apply(void 0,arguments)};return e.push(o),function(){n=!1,e=e.filter((function(t){return t!==o}))}},notifyListeners:function(){for(var t=arguments.length,n=Array(t),o=0;o<t;o++)n[o]=arguments[o];e.forEach((function(t){return t.apply(void 0,n)}))}}},b=!("undefined"==typeof window||!window.document||!window.document.createElement),g=function(t,e,n){return t.addEventListener?t.addEventListener(e,n,!1):t.attachEvent("on"+e,n)},w=function(t,e,n){return t.removeEventListener?t.removeEventListener(e,n,!1):t.detachEvent("on"+e,n)},O=function(t,e){return e(window.confirm(t))},x=function(){var t=window.navigator.userAgent;return(-1===t.indexOf("Android 2.")&&-1===t.indexOf("Android 4.0")||-1===t.indexOf("Mobile Safari")||-1!==t.indexOf("Chrome")||-1!==t.indexOf("Windows Phone"))&&(window.history&&"pushState"in window.history)},j=function(){return-1===window.navigator.userAgent.indexOf("Trident")},P=function(){return-1===window.navigator.userAgent.indexOf("Firefox")},E=function(t){return void 0===t.state&&-1===navigator.userAgent.indexOf("CriOS")},T="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(t){return typeof t}:function(t){return t&&"function"==typeof Symbol&&t.constructor===Symbol&&t!==Symbol.prototype?"symbol":typeof t},R=Object.assign||function(t){for(var e=1;e<arguments.length;e++){var n=arguments[e];for(var o in n)Object.prototype.hasOwnProperty.call(n,o)&&(t[o]=n[o])}return t},C=function(){try{return window.history.state||{}}catch(t){return{}}},S=function(){var t=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{};r(b,"Browser history needs a DOM");var e=window.history,n=x(),i=!j(),a=t.forceRefresh,c=void 0!==a&&a,u=t.getUserConfirmation,y=void 0===u?O:u,v=t.keyLength,P=void 0===v?6:v,S=t.basename?f(s(t.basename)):"",k=function(t){var e=t||{},n=e.key,r=e.state,i=window.location,a=i.pathname+i.search+i.hash;return o(!S||p(a,S)),S&&(a=l(a,S)),d(a,r,n)},A=function(){return Math.random().toString(36).substr(2,P)},_=m(),M=function(t){R(X,t),X.length=e.length,_.notifyListeners(X.location,X.action)},L=function(t){E(t)||H(k(t.state))},q=function(){H(k(C()))},U=!1,H=function(t){if(U)U=!1,M();else{_.confirmTransitionTo(t,"POP",y,(function(e){e?M({action:"POP",location:t}):W(t)}))}},W=function(t){var e=X.location,n=I.indexOf(e.key);-1===n&&(n=0);var o=I.indexOf(t.key);-1===o&&(o=0);var r=n-o;r&&(U=!0,F(r))},N=k(C()),I=[N.key],$=function(t){return S+h(t)},B=function(t,r){o(!("object"===(void 0===t?"undefined":T(t))&&void 0!==t.state&&void 0!==r));var i=d(t,r,A(),X.location);_.confirmTransitionTo(i,"PUSH",y,(function(t){if(t){var o=$(i),r=i.key,a=i.state;if(n)if(e.pushState({key:r,state:a},null,o),c)window.location.href=o;else{var s=I.indexOf(X.location.key),u=I.slice(0,-1===s?0:s+1);u.push(i.key),I=u,M({action:"PUSH",location:i})}else window.location.href=o}}))},D=function(t,r){o(!("object"===(void 0===t?"undefined":T(t))&&void 0!==t.state&&void 0!==r));var i=d(t,r,A(),X.location);_.confirmTransitionTo(i,"REPLACE",y,(function(t){if(t){var o=$(i),r=i.key,a=i.state;if(n)if(e.replaceState({key:r,state:a},null,o),c)window.location.replace(o);else{var s=I.indexOf(X.location.key);-1!==s&&(I[s]=i.key),M({action:"REPLACE",location:i})}else window.location.replace(o)}}))},F=function(t){e.go(t)},Y=function(){return F(-1)},K=function(){return F(1)},J=0,V=function(t){1===(J+=t)?(g(window,"popstate",L),i&&g(window,"hashchange",q)):0===J&&(w(window,"popstate",L),i&&w(window,"hashchange",q))},G=!1,z=function(){var t=arguments.length>0&&void 0!==arguments[0]&&arguments[0],e=_.setPrompt(t);return G||(V(1),G=!0),function(){return G&&(G=!1,V(-1)),e()}},Q=function(t){var e=_.appendListener(t);return V(1),function(){V(-1),e()}},X={length:e.length,action:"POP",location:N,createHref:$,push:B,replace:D,go:F,goBack:Y,goForward:K,block:z,listen:Q};return X},k=Object.assign||function(t){for(var e=1;e<arguments.length;e++){var n=arguments[e];for(var o in n)Object.prototype.hasOwnProperty.call(n,o)&&(t[o]=n[o])}return t},A={hashbang:{encodePath:function(t){return"!"===t.charAt(0)?t:"!/"+u(t)},decodePath:function(t){return"!"===t.charAt(0)?t.substr(1):t}},noslash:{encodePath:u,decodePath:s},slash:{encodePath:s,decodePath:s}},_=function(){var t=window.location.href,e=t.indexOf("#");return-1===e?"":t.substring(e+1)},M=function(t){return window.location.hash=t},L=function(t){var e=window.location.href.indexOf("#");window.location.replace(window.location.href.slice(0,e>=0?e:0)+"#"+t)},q=function(){var t=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{};r(b,"Hash history needs a DOM");var e=window.history,n=(P(),t.getUserConfirmation),i=void 0===n?O:n,a=t.hashType,c=void 0===a?"slash":a,u=t.basename?f(s(t.basename)):"",y=A[c],x=y.encodePath,j=y.decodePath,E=function(){var t=j(_());return o(!u||p(t,u)),u&&(t=l(t,u)),d(t)},T=m(),R=function(t){k(Z,t),Z.length=e.length,T.notifyListeners(Z.location,Z.action)},C=!1,S=null,q=function(){var t=_(),e=x(t);if(t!==e)L(e);else{var n=E(),o=Z.location;if(!C&&v(o,n))return;if(S===h(n))return;S=null,U(n)}},U=function(t){if(C)C=!1,R();else{T.confirmTransitionTo(t,"POP",i,(function(e){e?R({action:"POP",location:t}):H(t)}))}},H=function(t){var e=Z.location,n=$.lastIndexOf(h(e));-1===n&&(n=0);var o=$.lastIndexOf(h(t));-1===o&&(o=0);var r=n-o;r&&(C=!0,Y(r))},W=_(),N=x(W);W!==N&&L(N);var I=E(),$=[h(I)],B=function(t){return"#"+x(u+h(t))},D=function(t,e){var n=d(t,void 0,void 0,Z.location);T.confirmTransitionTo(n,"PUSH",i,(function(t){if(t){var e=h(n),o=x(u+e);if(_()!==o){S=e,M(o);var r=$.lastIndexOf(h(Z.location)),i=$.slice(0,-1===r?0:r+1);i.push(e),$=i,R({action:"PUSH",location:n})}else R()}}))},F=function(t,e){var n=d(t,void 0,void 0,Z.location);T.confirmTransitionTo(n,"REPLACE",i,(function(t){if(t){var e=h(n),o=x(u+e);_()!==o&&(S=e,L(o));var r=$.indexOf(h(Z.location));-1!==r&&($[r]=e),R({action:"REPLACE",location:n})}}))},Y=function(t){e.go(t)},K=function(){return Y(-1)},J=function(){return Y(1)},V=0,G=function(t){1===(V+=t)?g(window,"hashchange",q):0===V&&w(window,"hashchange",q)},z=!1,Q=function(){var t=arguments.length>0&&void 0!==arguments[0]&&arguments[0],e=T.setPrompt(t);return z||(G(1),z=!0),function(){return z&&(z=!1,G(-1)),e()}},X=function(t){var e=T.appendListener(t);return G(1),function(){G(-1),e()}},Z={length:e.length,action:"POP",location:I,createHref:B,push:D,replace:F,go:Y,goBack:K,goForward:J,block:Q,listen:X};return Z},U="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(t){return typeof t}:function(t){return t&&"function"==typeof Symbol&&t.constructor===Symbol&&t!==Symbol.prototype?"symbol":typeof t},H=Object.assign||function(t){for(var e=1;e<arguments.length;e++){var n=arguments[e];for(var o in n)Object.prototype.hasOwnProperty.call(n,o)&&(t[o]=n[o])}return t},W=function(t,e,n){return Math.min(Math.max(t,e),n)},N=function(){var t=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{},e=t.getUserConfirmation,n=t.initialEntries,r=void 0===n?["/"]:n,i=t.initialIndex,a=void 0===i?0:i,c=t.keyLength,s=void 0===c?6:c,u=m(),p=function(t){H(T,t),T.length=T.entries.length,u.notifyListeners(T.location,T.action)},l=function(){return Math.random().toString(36).substr(2,s)},f=W(a,0,r.length-1),y=r.map((function(t){return d(t,void 0,"string"==typeof t?l():t.key||l())})),v=h,b=function(t,n){o(!("object"===(void 0===t?"undefined":U(t))&&void 0!==t.state&&void 0!==n));var r=d(t,n,l(),T.location);u.confirmTransitionTo(r,"PUSH",e,(function(t){if(t){var e=T.index+1,n=T.entries.slice(0);n.length>e?n.splice(e,n.length-e,r):n.push(r),p({action:"PUSH",location:r,index:e,entries:n})}}))},g=function(t,n){o(!("object"===(void 0===t?"undefined":U(t))&&void 0!==t.state&&void 0!==n));var r=d(t,n,l(),T.location);u.confirmTransitionTo(r,"REPLACE",e,(function(t){t&&(T.entries[T.index]=r,p({action:"REPLACE",location:r}))}))},w=function(t){var n=W(T.index+t,0,T.entries.length-1),o=T.entries[n];u.confirmTransitionTo(o,"POP",e,(function(t){t?p({action:"POP",location:o,index:n}):p()}))},O=function(){return w(-1)},x=function(){return w(1)},j=function(t){var e=T.index+t;return e>=0&&e<T.entries.length},P=function(){var t=arguments.length>0&&void 0!==arguments[0]&&arguments[0];return u.setPrompt(t)},E=function(t){return u.appendListener(t)},T={length:y.length,action:"POP",location:y[f],index:f,entries:y,createHref:v,push:b,replace:g,go:w,goBack:O,goForward:x,canGo:j,block:P,listen:E};return T},I=Object.assign||function(t){for(var e=1;e<arguments.length;e++){var n=arguments[e];for(var o in n)Object.prototype.hasOwnProperty.call(n,o)&&(t[o]=n[o])}return t};function $(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}function B(t,e){if(!t)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return!e||"object"!=typeof e&&"function"!=typeof e?t:e}var D=function(t){function o(){var e,n;$(this,o);for(var r=arguments.length,i=Array(r),a=0;a<r;a++)i[a]=arguments[a];return e=n=B(this,t.call.apply(t,[this].concat(i))),n.state={match:n.computeMatch(n.props.history.location.pathname)},B(n,e)}return function(t,e){if("function"!=typeof e&&null!==e)throw new TypeError("Super expression must either be null or a function, not "+typeof e);t.prototype=Object.create(e&&e.prototype,{constructor:{value:t,enumerable:!1,writable:!0,configurable:!0}}),e&&(Object.setPrototypeOf?Object.setPrototypeOf(t,e):t.__proto__=e)}(o,t),o.prototype.getChildContext=function(){return{router:I({},this.context.router,{history:this.props.history,route:{location:this.props.history.location,match:this.state.match}})}},o.prototype.computeMatch=function(t){return{path:"/",url:"/",params:{},isExact:"/"===t}},o.prototype.componentWillMount=function(){var t=this,n=this.props,o=n.children,i=n.history;r(null==o||1===e.Children.count(o),"A <Router> may have only one child element"),this.unlisten=i.listen((function(){t.setState({match:t.computeMatch(i.location.pathname)})}))},o.prototype.componentWillReceiveProps=function(t){n(this.props.history===t.history)},o.prototype.componentWillUnmount=function(){this.unlisten()},o.prototype.render=function(){var t=this.props.children;return t?e.Children.only(t):null},o}(e.Component);function F(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}function Y(t,e){if(!t)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return!e||"object"!=typeof e&&"function"!=typeof e?t:e}D.propTypes={history:t.object.isRequired,children:t.node},D.contextTypes={router:t.object},D.childContextTypes={router:t.object.isRequired};var K=function(t){function o(){var e,n;F(this,o);for(var r=arguments.length,i=Array(r),a=0;a<r;a++)i[a]=arguments[a];return e=n=Y(this,t.call.apply(t,[this].concat(i))),n.history=S(n.props),Y(n,e)}return function(t,e){if("function"!=typeof e&&null!==e)throw new TypeError("Super expression must either be null or a function, not "+typeof e);t.prototype=Object.create(e&&e.prototype,{constructor:{value:t,enumerable:!1,writable:!0,configurable:!0}}),e&&(Object.setPrototypeOf?Object.setPrototypeOf(t,e):t.__proto__=e)}(o,t),o.prototype.componentWillMount=function(){n(!this.props.history)},o.prototype.render=function(){return e.createElement(D,{history:this.history,children:this.props.children})},o}(e.Component);function J(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}function V(t,e){if(!t)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return!e||"object"!=typeof e&&"function"!=typeof e?t:e}K.propTypes={basename:t.string,forceRefresh:t.bool,getUserConfirmation:t.func,keyLength:t.number,children:t.node};var G=function(t){function o(){var e,n;J(this,o);for(var r=arguments.length,i=Array(r),a=0;a<r;a++)i[a]=arguments[a];return e=n=V(this,t.call.apply(t,[this].concat(i))),n.history=q(n.props),V(n,e)}return function(t,e){if("function"!=typeof e&&null!==e)throw new TypeError("Super expression must either be null or a function, not "+typeof e);t.prototype=Object.create(e&&e.prototype,{constructor:{value:t,enumerable:!1,writable:!0,configurable:!0}}),e&&(Object.setPrototypeOf?Object.setPrototypeOf(t,e):t.__proto__=e)}(o,t),o.prototype.componentWillMount=function(){n(!this.props.history)},o.prototype.render=function(){return e.createElement(D,{history:this.history,children:this.props.children})},o}(e.Component);G.propTypes={basename:t.string,getUserConfirmation:t.func,hashType:t.oneOf(["hashbang","noslash","slash"]),children:t.node};var z=Object.assign||function(t){for(var e=1;e<arguments.length;e++){var n=arguments[e];for(var o in n)Object.prototype.hasOwnProperty.call(n,o)&&(t[o]=n[o])}return t};function Q(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}function X(t,e){if(!t)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return!e||"object"!=typeof e&&"function"!=typeof e?t:e}var Z=function(t){return!!(t.metaKey||t.altKey||t.ctrlKey||t.shiftKey)},tt=function(t){function n(){var e,o;Q(this,n);for(var r=arguments.length,i=Array(r),a=0;a<r;a++)i[a]=arguments[a];return e=o=X(this,t.call.apply(t,[this].concat(i))),o.handleClick=function(t){if(o.props.onClick&&o.props.onClick(t),!t.defaultPrevented&&0===t.button&&!o.props.target&&!Z(t)){t.preventDefault();var e=o.context.router.history,n=o.props,r=n.replace,i=n.to;r?e.replace(i):e.push(i)}},X(o,e)}return function(t,e){if("function"!=typeof e&&null!==e)throw new TypeError("Super expression must either be null or a function, not "+typeof e);t.prototype=Object.create(e&&e.prototype,{constructor:{value:t,enumerable:!1,writable:!0,configurable:!0}}),e&&(Object.setPrototypeOf?Object.setPrototypeOf(t,e):t.__proto__=e)}(n,t),n.prototype.render=function(){var t=this.props,n=(t.replace,t.to),o=t.innerRef,i=function(t,e){var n={};for(var o in t)e.indexOf(o)>=0||Object.prototype.hasOwnProperty.call(t,o)&&(n[o]=t[o]);return n}(t,["replace","to","innerRef"]);r(this.context.router,"You should not use <Link> outside a <Router>"),r(void 0!==n,'You must specify the "to" property');var a=this.context.router.history,c="string"==typeof n?d(n,null,null,a.location):n,s=a.createHref(c);return e.createElement("a",z({},i,{onClick:this.handleClick,href:s,ref:o}))},n}(e.Component);function et(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}function nt(t,e){if(!t)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return!e||"object"!=typeof e&&"function"!=typeof e?t:e}tt.propTypes={onClick:t.func,target:t.string,replace:t.bool,to:t.oneOfType([t.string,t.object]).isRequired,innerRef:t.oneOfType([t.string,t.func])},tt.defaultProps={replace:!1},tt.contextTypes={router:t.shape({history:t.shape({push:t.func.isRequired,replace:t.func.isRequired,createHref:t.func.isRequired}).isRequired}).isRequired};var ot=function(t){function o(){var e,n;et(this,o);for(var r=arguments.length,i=Array(r),a=0;a<r;a++)i[a]=arguments[a];return e=n=nt(this,t.call.apply(t,[this].concat(i))),n.history=N(n.props),nt(n,e)}return function(t,e){if("function"!=typeof e&&null!==e)throw new TypeError("Super expression must either be null or a function, not "+typeof e);t.prototype=Object.create(e&&e.prototype,{constructor:{value:t,enumerable:!1,writable:!0,configurable:!0}}),e&&(Object.setPrototypeOf?Object.setPrototypeOf(t,e):t.__proto__=e)}(o,t),o.prototype.componentWillMount=function(){n(!this.props.history)},o.prototype.render=function(){return e.createElement(D,{history:this.history,children:this.props.children})},o}(e.Component);ot.propTypes={initialEntries:t.array,initialIndex:t.number,getUserConfirmation:t.func,keyLength:t.number,children:t.node};var rt=Array.isArray||function(t){return"[object Array]"==Object.prototype.toString.call(t)},it=gt,at=lt,ct=function(t,e){return ht(lt(t,e))},st=ht,ut=bt,pt=new RegExp(["(\\\\.)","([\\/.])?(?:(?:\\:(\\w+)(?:\\(((?:\\\\.|[^\\\\()])+)\\))?|\\(((?:\\\\.|[^\\\\()])+)\\))([+*?])?|(\\*))"].join("|"),"g");function lt(t,e){for(var n,o=[],r=0,i=0,a="",c=e&&e.delimiter||"/";null!=(n=pt.exec(t));){var s=n[0],u=n[1],p=n.index;if(a+=t.slice(i,p),i=p+s.length,u)a+=u[1];else{var l=t[i],f=n[2],h=n[3],y=n[4],d=n[5],v=n[6],m=n[7];a&&(o.push(a),a="");var b=null!=f&&null!=l&&l!==f,g="+"===v||"*"===v,w="?"===v||"*"===v,O=n[2]||c,x=y||d;o.push({name:h||r++,prefix:f||"",delimiter:O,optional:w,repeat:g,partial:b,asterisk:!!m,pattern:x?dt(x):m?".*":"[^"+yt(O)+"]+?"})}}return i<t.length&&(a+=t.substr(i)),a&&o.push(a),o}function ft(t){return encodeURI(t).replace(/[\/?#]/g,(function(t){return"%"+t.charCodeAt(0).toString(16).toUpperCase()}))}function ht(t){for(var e=new Array(t.length),n=0;n<t.length;n++)"object"==typeof t[n]&&(e[n]=new RegExp("^(?:"+t[n].pattern+")$"));return function(n,o){for(var r="",i=n||{},a=(o||{}).pretty?ft:encodeURIComponent,c=0;c<t.length;c++){var s=t[c];if("string"!=typeof s){var u,p=i[s.name];if(null==p){if(s.optional){s.partial&&(r+=s.prefix);continue}throw new TypeError('Expected "'+s.name+'" to be defined')}if(rt(p)){if(!s.repeat)throw new TypeError('Expected "'+s.name+'" to not repeat, but received `'+JSON.stringify(p)+"`");if(0===p.length){if(s.optional)continue;throw new TypeError('Expected "'+s.name+'" to not be empty')}for(var l=0;l<p.length;l++){if(u=a(p[l]),!e[c].test(u))throw new TypeError('Expected all "'+s.name+'" to match "'+s.pattern+'", but received `'+JSON.stringify(u)+"`");r+=(0===l?s.prefix:s.delimiter)+u}}else{if(u=s.asterisk?encodeURI(p).replace(/[?#]/g,(function(t){return"%"+t.charCodeAt(0).toString(16).toUpperCase()})):a(p),!e[c].test(u))throw new TypeError('Expected "'+s.name+'" to match "'+s.pattern+'", but received "'+u+'"');r+=s.prefix+u}}else r+=s}return r}}function yt(t){return t.replace(/([.+*?=^!:${}()[\]|\/\\])/g,"\\$1")}function dt(t){return t.replace(/([=!:$\/()])/g,"\\$1")}function vt(t,e){return t.keys=e,t}function mt(t){return t.sensitive?"":"i"}function bt(t,e,n){rt(e)||(n=e||n,e=[]);for(var o=(n=n||{}).strict,r=!1!==n.end,i="",a=0;a<t.length;a++){var c=t[a];if("string"==typeof c)i+=yt(c);else{var s=yt(c.prefix),u="(?:"+c.pattern+")";e.push(c),c.repeat&&(u+="(?:"+s+u+")*"),i+=u=c.optional?c.partial?s+"("+u+")?":"(?:"+s+"("+u+"))?":s+"("+u+")"}}var p=yt(n.delimiter||"/"),l=i.slice(-p.length)===p;return o||(i=(l?i.slice(0,-p.length):i)+"(?:"+p+"(?=$))?"),i+=r?"$":o&&l?"":"(?="+p+"|$)",vt(new RegExp("^"+i,mt(n)),e)}function gt(t,e,n){return rt(e)||(n=e||n,e=[]),n=n||{},t instanceof RegExp?function(t,e){var n=t.source.match(/\((?!\?)/g);if(n)for(var o=0;o<n.length;o++)e.push({name:o,prefix:null,delimiter:null,optional:!1,repeat:!1,partial:!1,asterisk:!1,pattern:null});return vt(t,e)}(t,e):rt(t)?function(t,e,n){for(var o=[],r=0;r<t.length;r++)o.push(gt(t[r],e,n).source);return vt(new RegExp("(?:"+o.join("|")+")",mt(n)),e)}(t,e,n):function(t,e,n){return bt(lt(t,n),e,n)}(t,e,n)}it.parse=at,it.compile=ct,it.tokensToFunction=st,it.tokensToRegExp=ut;var wt={},Ot=0,xt=function(t,e){var n=""+e.end+e.strict+e.sensitive,o=wt[n]||(wt[n]={});if(o[t])return o[t];var r=[],i={re:it(t,r,e),keys:r};return Ot<1e4&&(o[t]=i,Ot++),i},jt=function(t){var e=arguments.length>1&&void 0!==arguments[1]?arguments[1]:{},n=arguments[2];"string"==typeof e&&(e={path:e});var o=e,r=o.path,i=o.exact,a=void 0!==i&&i,c=o.strict,s=void 0!==c&&c,u=o.sensitive,p=void 0!==u&&u;if(null==r)return n;var l=xt(r,{end:a,strict:s,sensitive:p}),f=l.re,h=l.keys,y=f.exec(t);if(!y)return null;var d=y[0],v=y.slice(1),m=t===d;return a&&!m?null:{path:r,url:"/"===r&&""===d?"/":d,isExact:m,params:h.reduce((function(t,e,n){return t[e.name]=v[n],t}),{})}},Pt=Object.assign||function(t){for(var e=1;e<arguments.length;e++){var n=arguments[e];for(var o in n)Object.prototype.hasOwnProperty.call(n,o)&&(t[o]=n[o])}return t};function Et(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}function Tt(t,e){if(!t)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return!e||"object"!=typeof e&&"function"!=typeof e?t:e}var Rt=function(t){return 0===e.Children.count(t)},Ct=function(t){function o(){var e,n;Et(this,o);for(var r=arguments.length,i=Array(r),a=0;a<r;a++)i[a]=arguments[a];return e=n=Tt(this,t.call.apply(t,[this].concat(i))),n.state={match:n.computeMatch(n.props,n.context.router)},Tt(n,e)}return function(t,e){if("function"!=typeof e&&null!==e)throw new TypeError("Super expression must either be null or a function, not "+typeof e);t.prototype=Object.create(e&&e.prototype,{constructor:{value:t,enumerable:!1,writable:!0,configurable:!0}}),e&&(Object.setPrototypeOf?Object.setPrototypeOf(t,e):t.__proto__=e)}(o,t),o.prototype.getChildContext=function(){return{router:Pt({},this.context.router,{route:{location:this.props.location||this.context.router.route.location,match:this.state.match}})}},o.prototype.computeMatch=function(t,e){var n=t.computedMatch,o=t.location,i=t.path,a=t.strict,c=t.exact,s=t.sensitive;if(n)return n;r(e,"You should not use <Route> or withRouter() outside a <Router>");var u=e.route,p=(o||u.location).pathname;return jt(p,{path:i,strict:a,exact:c,sensitive:s},u.match)},o.prototype.componentWillMount=function(){n(!(this.props.component&&this.props.render)),n(!(this.props.component&&this.props.children&&!Rt(this.props.children))),n(!(this.props.render&&this.props.children&&!Rt(this.props.children)))},o.prototype.componentWillReceiveProps=function(t,e){n(!(t.location&&!this.props.location)),n(!(!t.location&&this.props.location)),this.setState({match:this.computeMatch(t,e.router)})},o.prototype.render=function(){var t=this.state.match,n=this.props,o=n.children,r=n.component,i=n.render,a=this.context.router,c=a.history,s=a.route,u=a.staticContext,p={match:t,location:this.props.location||s.location,history:c,staticContext:u};return r?t?e.createElement(r,p):null:i?t?i(p):null:"function"==typeof o?o(p):o&&!Rt(o)?e.Children.only(o):null},o}(e.Component);Ct.propTypes={computedMatch:t.object,path:t.string,exact:t.bool,strict:t.bool,sensitive:t.bool,component:t.func,render:t.func,children:t.oneOfType([t.func,t.node]),location:t.object},Ct.contextTypes={router:t.shape({history:t.object.isRequired,route:t.object.isRequired,staticContext:t.object})},Ct.childContextTypes={router:t.object.isRequired};var St=Object.assign||function(t){for(var e=1;e<arguments.length;e++){var n=arguments[e];for(var o in n)Object.prototype.hasOwnProperty.call(n,o)&&(t[o]=n[o])}return t},kt="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(t){return typeof t}:function(t){return t&&"function"==typeof Symbol&&t.constructor===Symbol&&t!==Symbol.prototype?"symbol":typeof t};var At=function(t){var n=t.to,o=t.exact,r=t.strict,i=t.location,a=t.activeClassName,c=t.className,s=t.activeStyle,u=t.style,p=t.isActive,l=t["aria-current"],f=function(t,e){var n={};for(var o in t)e.indexOf(o)>=0||Object.prototype.hasOwnProperty.call(t,o)&&(n[o]=t[o]);return n}(t,["to","exact","strict","location","activeClassName","className","activeStyle","style","isActive","aria-current"]),h="object"===(void 0===n?"undefined":kt(n))?n.pathname:n,y=h&&h.replace(/([.+*?=^!:${}()[\]|/\\])/g,"\\$1");return e.createElement(Ct,{path:y,exact:o,strict:r,location:i,children:function(t){var o=t.location,r=t.match,i=!!(p?p(r,o):r);return e.createElement(tt,St({to:n,className:i?[c,a].filter((function(t){return t})).join(" "):c,style:i?St({},u,s):u,"aria-current":i&&l||null},f))}})};function _t(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}function Mt(t,e){if(!t)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return!e||"object"!=typeof e&&"function"!=typeof e?t:e}At.propTypes={to:tt.propTypes.to,exact:t.bool,strict:t.bool,location:t.object,activeClassName:t.string,className:t.string,activeStyle:t.object,style:t.object,isActive:t.func,"aria-current":t.oneOf(["page","step","location","date","time","true"])},At.defaultProps={activeClassName:"active","aria-current":"page"};var Lt=function(t){function e(){return _t(this,e),Mt(this,t.apply(this,arguments))}return function(t,e){if("function"!=typeof e&&null!==e)throw new TypeError("Super expression must either be null or a function, not "+typeof e);t.prototype=Object.create(e&&e.prototype,{constructor:{value:t,enumerable:!1,writable:!0,configurable:!0}}),e&&(Object.setPrototypeOf?Object.setPrototypeOf(t,e):t.__proto__=e)}(e,t),e.prototype.enable=function(t){this.unblock&&this.unblock(),this.unblock=this.context.router.history.block(t)},e.prototype.disable=function(){this.unblock&&(this.unblock(),this.unblock=null)},e.prototype.componentWillMount=function(){r(this.context.router,"You should not use <Prompt> outside a <Router>"),this.props.when&&this.enable(this.props.message)},e.prototype.componentWillReceiveProps=function(t){t.when?this.props.when&&this.props.message===t.message||this.enable(t.message):this.disable()},e.prototype.componentWillUnmount=function(){this.disable()},e.prototype.render=function(){return null},e}(e.Component);Lt.propTypes={when:t.bool,message:t.oneOfType([t.func,t.string]).isRequired},Lt.defaultProps={when:!0},Lt.contextTypes={router:t.shape({history:t.shape({block:t.func.isRequired}).isRequired}).isRequired};var qt={},Ut=0,Ht=function(t){var e=t,n=qt[e]||(qt[e]={});if(n[t])return n[t];var o=it.compile(t);return Ut<1e4&&(n[t]=o,Ut++),o},Wt=function(){var t=arguments.length>0&&void 0!==arguments[0]?arguments[0]:"/",e=arguments.length>1&&void 0!==arguments[1]?arguments[1]:{};if("/"===t)return t;var n=Ht(t);return n(e,{pretty:!0})},Nt=Object.assign||function(t){for(var e=1;e<arguments.length;e++){var n=arguments[e];for(var o in n)Object.prototype.hasOwnProperty.call(n,o)&&(t[o]=n[o])}return t};function It(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}function $t(t,e){if(!t)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return!e||"object"!=typeof e&&"function"!=typeof e?t:e}var Bt=function(t){function e(){return It(this,e),$t(this,t.apply(this,arguments))}return function(t,e){if("function"!=typeof e&&null!==e)throw new TypeError("Super expression must either be null or a function, not "+typeof e);t.prototype=Object.create(e&&e.prototype,{constructor:{value:t,enumerable:!1,writable:!0,configurable:!0}}),e&&(Object.setPrototypeOf?Object.setPrototypeOf(t,e):t.__proto__=e)}(e,t),e.prototype.isStatic=function(){return this.context.router&&this.context.router.staticContext},e.prototype.componentWillMount=function(){r(this.context.router,"You should not use <Redirect> outside a <Router>"),this.isStatic()&&this.perform()},e.prototype.componentDidMount=function(){this.isStatic()||this.perform()},e.prototype.componentDidUpdate=function(t){var e=d(t.to),o=d(this.props.to);v(e,o)?n(!1,"You tried to redirect to the same route you're currently on: \""+o.pathname+o.search+'"'):this.perform()},e.prototype.computeTo=function(t){var e=t.computedMatch,n=t.to;return e?"string"==typeof n?Wt(n,e.params):Nt({},n,{pathname:Wt(n.pathname,e.params)}):n},e.prototype.perform=function(){var t=this.context.router.history,e=this.props.push,n=this.computeTo(this.props);e?t.push(n):t.replace(n)},e.prototype.render=function(){return null},e}(e.Component);Bt.propTypes={computedMatch:t.object,push:t.bool,from:t.string,to:t.oneOfType([t.string,t.object]).isRequired},Bt.defaultProps={push:!1},Bt.contextTypes={router:t.shape({history:t.shape({push:t.func.isRequired,replace:t.func.isRequired}).isRequired,staticContext:t.object}).isRequired};var Dt=Object.assign||function(t){for(var e=1;e<arguments.length;e++){var n=arguments[e];for(var o in n)Object.prototype.hasOwnProperty.call(n,o)&&(t[o]=n[o])}return t};function Ft(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}function Yt(t,e){if(!t)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return!e||"object"!=typeof e&&"function"!=typeof e?t:e}var Kt=function(t){return"/"===t.charAt(0)?t:"/"+t},Jt=function(t,e){return t?Dt({},e,{pathname:Kt(t)+e.pathname}):e},Vt=function(t,e){if(!t)return e;var n=Kt(t);return 0!==e.pathname.indexOf(n)?e:Dt({},e,{pathname:e.pathname.substr(n.length)})},Gt=function(t){return"string"==typeof t?t:h(t)},zt=function(t){return function(){r(!1,"You cannot %s with <StaticRouter>",t)}},Qt=function(){},Xt=function(t){function o(){var e,n;Ft(this,o);for(var r=arguments.length,i=Array(r),a=0;a<r;a++)i[a]=arguments[a];return e=n=Yt(this,t.call.apply(t,[this].concat(i))),n.createHref=function(t){return Kt(n.props.basename+Gt(t))},n.handlePush=function(t){var e=n.props,o=e.basename,r=e.context;r.action="PUSH",r.location=Jt(o,d(t)),r.url=Gt(r.location)},n.handleReplace=function(t){var e=n.props,o=e.basename,r=e.context;r.action="REPLACE",r.location=Jt(o,d(t)),r.url=Gt(r.location)},n.handleListen=function(){return Qt},n.handleBlock=function(){return Qt},Yt(n,e)}return function(t,e){if("function"!=typeof e&&null!==e)throw new TypeError("Super expression must either be null or a function, not "+typeof e);t.prototype=Object.create(e&&e.prototype,{constructor:{value:t,enumerable:!1,writable:!0,configurable:!0}}),e&&(Object.setPrototypeOf?Object.setPrototypeOf(t,e):t.__proto__=e)}(o,t),o.prototype.getChildContext=function(){return{router:{staticContext:this.props.context}}},o.prototype.componentWillMount=function(){n(!this.props.history)},o.prototype.render=function(){var t=this.props,n=t.basename,o=(t.context,t.location),r=function(t,e){var n={};for(var o in t)e.indexOf(o)>=0||Object.prototype.hasOwnProperty.call(t,o)&&(n[o]=t[o]);return n}(t,["basename","context","location"]),i={createHref:this.createHref,action:"POP",location:Vt(n,d(o)),push:this.handlePush,replace:this.handleReplace,go:zt("go"),goBack:zt("goBack"),goForward:zt("goForward"),listen:this.handleListen,block:this.handleBlock};return e.createElement(D,Dt({},r,{history:i}))},o}(e.Component);function Zt(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}function te(t,e){if(!t)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return!e||"object"!=typeof e&&"function"!=typeof e?t:e}Xt.propTypes={basename:t.string,context:t.object.isRequired,location:t.oneOfType([t.string,t.object])},Xt.defaultProps={basename:"",location:"/"},Xt.childContextTypes={router:t.object.isRequired};var ee=function(t){function o(){return Zt(this,o),te(this,t.apply(this,arguments))}return function(t,e){if("function"!=typeof e&&null!==e)throw new TypeError("Super expression must either be null or a function, not "+typeof e);t.prototype=Object.create(e&&e.prototype,{constructor:{value:t,enumerable:!1,writable:!0,configurable:!0}}),e&&(Object.setPrototypeOf?Object.setPrototypeOf(t,e):t.__proto__=e)}(o,t),o.prototype.componentWillMount=function(){r(this.context.router,"You should not use <Switch> outside a <Router>")},o.prototype.componentWillReceiveProps=function(t){n(!(t.location&&!this.props.location)),n(!(!t.location&&this.props.location))},o.prototype.render=function(){var t=this.context.router.route,n=this.props.children,o=this.props.location||t.location,r=void 0,i=void 0;return e.Children.forEach(n,(function(n){if(null==r&&e.isValidElement(n)){var a=n.props,c=a.path,s=a.exact,u=a.strict,p=a.sensitive,l=a.from,f=c||l;i=n,r=jt(o.pathname,{path:f,exact:s,strict:u,sensitive:p},t.match)}})),r?e.cloneElement(i,{location:o,computedMatch:r}):null},o}(e.Component);ee.contextTypes={router:t.shape({route:t.object.isRequired}).isRequired},ee.propTypes={children:t.node,location:t.object};var ne={childContextTypes:!0,contextTypes:!0,defaultProps:!0,displayName:!0,getDefaultProps:!0,getDerivedStateFromProps:!0,mixins:!0,propTypes:!0,type:!0},oe={name:!0,length:!0,prototype:!0,caller:!0,callee:!0,arguments:!0,arity:!0},re=Object.defineProperty,ie=Object.getOwnPropertyNames,ae=Object.getOwnPropertySymbols,ce=Object.getOwnPropertyDescriptor,se=Object.getPrototypeOf,ue=se&&se(Object);var pe=function t(e,n,o){if("string"!=typeof n){if(ue){var r=se(n);r&&r!==ue&&t(e,r,o)}var i=ie(n);ae&&(i=i.concat(ae(n)));for(var a=0;a<i.length;++a){var c=i[a];if(!(ne[c]||oe[c]||o&&o[c])){var s=ce(n,c);try{re(e,c,s)}catch(t){}}}return e}return e},le=Object.assign||function(t){for(var e=1;e<arguments.length;e++){var n=arguments[e];for(var o in n)Object.prototype.hasOwnProperty.call(n,o)&&(t[o]=n[o])}return t};var fe=function(n){var o=function(t){var o=t.wrappedComponentRef,r=function(t,e){var n={};for(var o in t)e.indexOf(o)>=0||Object.prototype.hasOwnProperty.call(t,o)&&(n[o]=t[o]);return n}(t,["wrappedComponentRef"]);return e.createElement(Ct,{children:function(t){return e.createElement(n,le({},r,t,{ref:o}))}})};return o.displayName="withRouter("+(n.displayName||n.name)+")",o.WrappedComponent=n,o.propTypes={wrappedComponentRef:t.func},pe(o,n)};export{K as BrowserRouter,G as HashRouter,tt as Link,ot as MemoryRouter,At as NavLink,Lt as Prompt,Bt as Redirect,Ct as Route,D as Router,Xt as StaticRouter,ee as Switch,Wt as generatePath,jt as matchPath,fe as withRouter};
//# sourceMappingURL=react-router-dom.js.map
