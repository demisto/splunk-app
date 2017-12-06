require.config({
    paths: {
        "app": "../app"
    }
});
require([
	   'splunkjs/mvc/searchmanager',
	   'splunkjs/mvc',
	   'jquery',
	   'css!../app/demisto/donutchart.css',	
       'splunkjs/mvc/simplexml/ready!',	  
       'underscore',
	   'splunkjs/ready!'
	   ],function(SearchManager,mvc,$ ){
		   //console.log("Compromised_Hosts")
			
			function onClickHandler(e) 
			{
				e.preventDefault();
				console.log("Clicked the chart: ", e.value);
				
		
			}
		}
);