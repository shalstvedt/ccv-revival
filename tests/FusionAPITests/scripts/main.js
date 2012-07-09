function connect(host, port) {
	tcpClient = new TcpClient(host, port);
	tcpClient.connect(function() {
	  tcpClient.addResponseListener(function(data) {
		$('#divDataRaw').empty();
		$('#divDataRaw').append(data);
		if($('#divDataRaw').val() == "") { $('#status').attr("src", "red.png");}
		else { $('#status').attr("src", "green.png");}
		});
	});
}

$(document).ready(function () {
	var host = '127.0.0.1';
	var port = 7500;
	connect(host, port);

	$('#requests').change(function() {
		if(this.value == "null")
		{
			$('#divDataRaw').empty(); 
			return;
		}
		if(this.value == "/workflow/quit"){
			if(!confirm('Are you sure you want to quit?')) {return;}
		}
		var jsonRequest = {"jsonrpc": "2.0", 
			"method": this.value,
			"id" : 123
		};
		var stringreq = JSON.stringify(jsonRequest);
		tcpClient.sendMessage(stringreq, function() {$('#status').attr("src", "orange.png");});
	});
});

/*

var tcp2 = new TcpClient('127.0.0.1', 7500);

tcp2.connect(function() {
      tcp2.addResponseListener(function(data) {
        $('#divDataRaw').empty();
		$('#divDataRaw').append(data);
		if($('#divDataRaw').val() == "") { $('#status').attr("src", "red.png");}
		else { $('#status').attr("src", "green.png");}
     });
});
	
tcp2.sendMessage(JSON.stringify({"jsonrpc": "2.0", 
	"method": "nui_list_dynamic",
	"params": {
		"hostername" : "blah"
	},
	"id" : 123
}), function() {$('#status').attr("src", "red.png");});

*/