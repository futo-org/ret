const ret = {
	re_log: Module.cwrap('re_log', 'void', ['pointer', 'string']),
	log: function(str) {
		ret.re_log(0, str);
	},

	main: function() {
		ret.log("Hello\n");
	},
};

Module['onRuntimeInitialized'] = ret.main;
