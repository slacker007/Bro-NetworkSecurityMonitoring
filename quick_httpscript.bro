
# Modified by:
# @killswitch-gui
# @realSlacker007

@load base/protocols/conn/main
@load base/frameworks/sumstats/plugins/average

event http_entity_data (c: connection, is_orig: bool, length: count, data: string)
{

#print c;

SumStats::observe ("conn established", SumStats::Key(), SumStats::Observation($num=1));

}

event bro_init()
	{
	
	local r1 = SumStats::Reducer($stream="conn established", $apply=set (SumStats::SUM));

	SumStats::create([$name = "counting connections",
			  $epoch = 1min, 
			  $reducers = set(r1),
			  $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
				{
				
#				print fmt("number of connections established %.0f", result ["conn established"]$sum);
				}]);
	}




