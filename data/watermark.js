/* Copyright 2006 VMware, Inc.	All rights reserved. -- VMware Confidential */

/**
 * Position background image watermark.png in the bottom left content area,
 * above and abutting the copyright footer. We have to hard code some values
 * for now and account for the fact that Internet Explorer reports the
 * offsetHeight of the footer div differently for all three (ESX Server,
 * VirtualCenter, and VirtualCenter without Web Access) pages.
 */

var ie = false;
/*@cc_on
ie = true;
@*/

//Setting the resource for the locale defaulting to load en resource.
var serverPath, langID;
var cLocale	= navigator.userLanguage;
if (cLocale == null)
   cLocale = navigator.language;
  
if(cLocale.indexOf("zh") > -1) {
	langID = 'zh-CN';
} else if (cLocale.indexOf("tw") > -1 || cLocale.indexOf("hk") > -1 ) {
		langID = 'zh-TW';
} else {
	langID = '' + cLocale.charAt(0) + cLocale.charAt(1);
}

document.write('<script language="JavaScript" src="./' 
				  + langID + '/welcomeRes.js"> type="text/javascript"></script>');
				
function $(s) {
   return document.getElementById(s);
}

function getOffsetTop(o) {
   var ot = o.offsetTop;
   while (o = o.offsetParent) {
      ot += o.offsetTop;
   }

   return ot;
}

function setOffsetHeight(o, h) {
   if (null != h) {
      o.style.height = h + "px";

      if (o.offsetHeight > h) {
	 var diff = o.offsetHeight - h;
	 o.style.height = (h - diff) + "px";
      }
   }

   return o.offsetHeight;
}

function getOffsetHeight(o) {
   return setOffsetHeight(o);
}

function initPage() {
   var main = $("main");
   var header = $("header");
   var content = $("content");
   var sidebar = $("sidebar");
   
   // Make sure the header and content divs occupy a minimum amount of vertical
   // real estate so their background images appear as expected.
   if (getOffsetHeight(header) < 92) {
      setOffsetHeight(header, 92);
   }
   setOffsetHeight(content, getOffsetHeight(content) + 166);

   // 222 is the pixel height of the background image watermark.png.
   var offset = -222;
   
   if (ie) {
      var sidebarTop = getOffsetTop(sidebar);
      var sidebarHeight = getOffsetHeight(sidebar);
      var sidebarOffset = sidebarTop + sidebarHeight;
      
      var contentTop = getOffsetTop(content);
      var contentHeight = getOffsetHeight(content);
      var contentOffset = contentTop + contentHeight;
      
      // Differences in hardcoded offset are likely due to differences in
      // bottom margins between the sidebar and content divs. Margins have been
      // specified in em units, so there's no straightforward way to include
      // the real margin in this calculation.
      offset += (sidebarOffset > contentOffset 
	 ? sidebarOffset + 28
	 : contentOffset + 38);
   } else {
      // Why 7? Because it works for now.
      offset += getOffsetHeight(main) - getOffsetHeight($("footer")) - 7;
   }
   
   main.style.backgroundPosition = "0% " + offset + "px";
}

onload = (document.getElementById) ? initPage : null;
