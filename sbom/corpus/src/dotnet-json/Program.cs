using Newtonsoft.Json;
var o = JsonConvert.DeserializeObject<Dictionary<string, int>>("{\"atk\":0}");
Console.WriteLine(JsonConvert.SerializeObject(o));
