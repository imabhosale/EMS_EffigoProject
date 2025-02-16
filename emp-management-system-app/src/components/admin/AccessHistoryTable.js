import axios from "axios";
import { useEffect, useState } from "react";

function AccessHistoryTable() {
    const [accessHistory, setAccessHistory] = useState([]);
    const fetchAccessHistory = async () => {
        try {
            const token = sessionStorage.getItem("jwtToken");

            const response = await axios.get("http://localhost:8999/users/accessHistory", {
                headers: {
                    "Authorization": `Bearer ${token}`
                }
            });
            setAccessHistory(response.data)
        } catch (error) {
            console.error(error.message);
        }
    }

    useEffect(() => {
        fetchAccessHistory();
    }, []);

    return (
        <div className="container">
            <div className="d-flex justify-content-center p-3">
                <h3>Access History</h3>
            </div>
            <table className="table table-striped table-light table-bordered table-hover">
                <thead>
                    <tr>
                        <th>User Id</th>
                        <th>Date</th>
                        <th>Time</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {accessHistory.map((item,index) => {
                        return (
                            <tr key = {index}>
                                <td>{item.userId}</td>
                                <td>{new Date(item.time).toDateString()}</td>
                                <td>{new Date(item.time).toTimeString()}</td>
                                <td>{item.status ? "Login" : "Logout"}</td>
                              </tr>
                        )
                    })}
                </tbody>
            </table>
        </div>
    )
}

export default AccessHistoryTable;