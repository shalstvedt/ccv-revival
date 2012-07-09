var host = '127.0.0.1';
var port = 7500;

function connect(host, port) {
	$('#status').attr("src", "grey.png");
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
	connect(host, port);

	$('#requests').change(function() {
		$('#divDataSent').empty();
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
			"id" : 123,
			"params" : {"pipeline" : "root",
						"module" : "nuiAudioOutputModule",
						"moduleId" : 1}
		};
		var stringreq = JSON.stringify(jsonRequest);
		$('#divDataSent').append(stringreq);
		tcpClient.sendMessage(stringreq, function() {$('#divDataRaw').empty(); $('#status').attr("src", "orange.png");});
	});
});

$('#reload').click(function(){connect(host, port);})

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