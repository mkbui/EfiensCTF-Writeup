function enter(){
	var x = document.getElementById('usrname').value;
	var y = document.getElementById('passwd').value;
	var _x = [ 0x50, 0x05, 0x21, 0x09, 0x0b, 0x5f, 0x0a];
	var _y = [ 0x24, 0x5f, 0x38, 0x1c, 0x1c, 0x3a, 0x1f, 0x1e, 0x1c, 0x45, 0x38, 0x0a, 0x1f, 0x36, 0x47, 0x00, 0x3c, 0x5c, 0x02, 0x1f, 0x6c, 0x07, 0x11];
	
	var i;
	var name = '';
	for (i = 0; i < x.length; i++) {
		  name += String.fromCharCode(x.charCodeAt(i) ^ _x[i]);		
	}

	var sekret = '';
	for (i = 0; i < y.length; i++) {
		  sekret += String.fromCharCode(y.charCodeAt(i) ^ _y[i]);
	}

	magik_quote = name + '_' + sekret;
	if (magik_quote == "diamond_in_the_rough,is_that_u?") {
		alert("You are either Aladdin or a very skilled hacker :))) Here is your treasure: efiensctf{" + x + '_' + y + '}');
	}
	else {
		alert("You are not the one. LEAVE IMMEDIATELY !!!")
	}

	
}
