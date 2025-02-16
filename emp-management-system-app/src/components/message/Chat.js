import React, { useEffect, useState } from "react";
import { API_ENDPOINTS } from "../config/Config";
import axios from "axios";
// import "./Chat.css";
import "jwt-decode";
import { jwtDecode } from "jwt-decode";

function Chat() {

    const [messages, setMessages] = useState([]);
    const [message, setMessage] = useState("");

    const [contacts, setContacts] = useState([]);
    const [currentContact, setCurrentContact] = useState(2);

    const [searchQuery, setSearchQuery] = useState("");
    const [currentUserId, setCurrentUserId] = useState(1);
    const handleTextChange = (event) => {
        setMessage(event.target.value);
    }   

    const handleKeyDownMessage = (event) => {
        if (event.key === "Enter") sendMessage();
    }

    const handleKeyDownSearchQuery = (event) => {
        if (event.key === "Enter") {
            fetchId();
        }
    }

    const handlePanelClick = (id) => {
        setCurrentContact(id);
    }

    const handleSearchQuery = (event) => {  
        setSearchQuery(event.target.value);
    }

    const fetchMessages = async () => {
        try {
            const token = sessionStorage.getItem("jwtToken");
            const response = await axios.get(API_ENDPOINTS.GET_MESSAGES + "/" + currentContact, {
                headers: { Authorization: `Bearer ${token}` },
            });
            setMessages(response.data);
        } catch (error) {
            console.error("Error fetching users", error);
        }
    };


    const fetchContacts = async () => {
        try {
            const token = sessionStorage.getItem("jwtToken");
            const response = await axios.get(API_ENDPOINTS.GET_CONTACTS, {
                headers: { Authorization: `Bearer ${token}` },
            });
            setContacts(response.data);
        } catch (error) {
            console.error("Error fetching users", error);
        }
    };

    const sendMessage = async () => {
        try {
            const token = sessionStorage.getItem("jwtToken");
            await axios.post(API_ENDPOINTS.SEND_MESSAGES, {
                "message": message,
                "senderId": currentUserId,
                "receiverId": currentContact
            },
                {
                    headers: {
                        "Authorization": `Bearer ${token}`,
                        "Content-Type": "application/json"
                    },
                });
            fetchMessages();
            setMessage("");
            console.log(currentContact);
            console.log(currentUserId)
        } catch (error) {
            console.error("Error fetching users", error);
        }
    };

    const fetchId = async () =>{
        try {
            const token = sessionStorage.getItem("jwtToken");
            console.log(API_ENDPOINTS.GET_ID + `/${searchQuery}`)
            const response = await axios.get(API_ENDPOINTS.GET_ID + `/${searchQuery}`, {
                headers: { Authorization: `Bearer ${token}` },
            });
            console.log(response.data);
            setCurrentContact(response.data);
            setContacts(contacts.concat(response.data));
        } catch (error) {
            console.error("Error fetching users", error);
        }
    }

    useEffect(() => {
        const token = sessionStorage.getItem("jwtToken");
        const email = jwtDecode(token).sub;
        axios.get(API_ENDPOINTS.GET_ID + `/${email}`, {
            headers: { Authorization: `Bearer ${token}` },
        })
            .then((response) => {
                setCurrentUserId(response.data);
            })
            .catch((error) => {
                console.error("Error fetching users", error);
            });
    }, []);

    useEffect(() => {
        fetchContacts();
    }, []);

    useEffect(() => {
        fetchMessages();
    }, [currentContact]);


    return (

        <div className="container">
            <div className="p-2">
                <input type = "text" placeholder="Enter Contact Email" value={searchQuery} onChange={handleSearchQuery} onKeyDown={handleKeyDownSearchQuery} className="form-control"></input>
            </div>
            <div className="card">
                <div className="card-header">
                    <h5>Chat</h5>
                </div>
                <div className="d-flex flex-row justify-content-between">
                    <div className="container p-2 w-50">
                        {contacts.map((userId) => (
                            <div className="card card-sm bg-light border m-2" onClick={() => handlePanelClick(userId)}>
                                <div className="card-body" style={{ cursor: "pointer" }}>UserId {userId}</div>
                            </div>
                        ))}

                    </div>

                    <div className="vr"></div>

                    <div className="container p-0">
                        <div className="card-body overflow-auto " style={{ height: "500px" }}>
                            {messages.map((message) => {
                                return (
                                    <div className={`d-flex justify-content-${message.receiverId === currentContact ? 'end' : 'start'}`} >
                                        <div className={`card p-1 m-1 rounded-1 ${message.receiverId === currentContact ? 'bg-light' : 'bg-secondary text-white'}`} style={{ width: "fit-content" }}>
                                            {message.message}
                                        </div>
                                    </div>
                                );
                            })}
                        </div>

                        <div className="card-footer">
                            <input className="form-control" onChange={handleTextChange} value={message} onKeyDown={handleKeyDownMessage}></input>
                        </div>

                    </div>
                </div>
            </div>
        </div>

    );
}

export default Chat;