import React, { useEffect, useState } from "react";
import { API_ENDPOINTS } from "../config/Config";
import axios from "axios";
// import "./Chat.css";
import "jwt-decode";
import { jwtDecode } from "jwt-decode";
function Chat() {

    const [chatMessages, setChatMessages] = useState([]);
    const [isChatMessagesLoading, setIsChatMessagesLoading] = useState(false)
    const [typedMessage, setTypedMessage] = useState("");

    const [contactList, setContactList] = useState([]);
    const [selectedContact, setSelectedContact] = useState(2);

    const [searchQuery, setSearchQuery] = useState("");
    const [isQueryFocused, setIsQueryFocused] = useState(false);
    const [queryContactList, setQueryContactList] = useState([])
    const [loggedUserId, setLoggedUserId] = useState(1);
    const [testResponse, setTestResponse] = useState({});
    const handleMessageChange = (event) => {
        setTypedMessage(event.target.value);
    }

    const handleMessageEnter = (event) => {
        if (event.key === "Enter") {
            sendTypedMessage();
        }
    }

    const handleMessageSend = () => {
        sendTypedMessage();
    }

    const handleQueryChange = (event) => {
        console.log("Query Changed");
        setSearchQuery(event.target.value);
    }

    const handleQueryEnter = (event) => {
        if (event.key === "Enter") {
            fetchContactIdWithQuery();
            fetchSelectedContact();
        }
    }

    const handleContactClick = (id) => {
        setSelectedContact(id);
    }

    const fetchChatMessages = async () => {
        setIsChatMessagesLoading(true)
        try {
            const token = sessionStorage.getItem("jwtToken");
            const response = await axios.get(API_ENDPOINTS.GET_MESSAGES + "/" + selectedContact, {
                headers: { Authorization: `Bearer ${token}` },
            });

            setChatMessages(response.data);
        } catch (error) {
            console.error("Error Fetching Messages for the chat...", error);
        } finally {
            setIsChatMessagesLoading(false)
        }
    };

    const fetchContactList = async () => {
        try {
            const token = sessionStorage.getItem("jwtToken");
            const response = await axios.get(API_ENDPOINTS.GET_CONTACTS, {
                headers: { Authorization: `Bearer ${token}` },
            });

            console.log("FETCHED contact list: ", response.data)
            setContactList(response.data);
        } catch (error) {
            console.error("Error fetching users:", error);
        }
    };

    const fetchSelectedContact = async () => {
        try {
            const token = sessionStorage.getItem("jwtToken");
            console.log("Getting Contact from : ", API_ENDPOINTS.GET_CONTACT + `/${selectedContact}`);
            const response = await axios.get(API_ENDPOINTS.GET_CONTACT + `/${selectedContact}`, {
                headers: { Authorization: `Bearer ${token}` },
            });
            console.log("Data for selected contact: ", response.data);
            let found = false;
            contactList.forEach((contact) => {
                if (contact.id === selectedContact) {
                    found = true;
                }
            })
            if (!found) {
                setContactList(contactList.concat(response.data));
            }
        } catch (error) {
            console.log("Error fetching selected Contact", error.message);
        }
    };

    const sendTypedMessage = async () => {
        try {
            const token = sessionStorage.getItem("jwtToken");
            await axios.post(API_ENDPOINTS.SEND_MESSAGES, {
                "message": typedMessage,
                "senderId": loggedUserId,
                "receiverId": selectedContact
            },
                {
                    headers: {
                        "Authorization": `Bearer ${token}`,
                        "Content-Type": "application/json"
                    },
                });

            fetchChatMessages();
            setTypedMessage("");
        } catch (error) {
            console.error("Error Sending Message", error);
        }
    };

    const fetchContactIdWithQuery = async () => {
        try {
            const token = sessionStorage.getItem("jwtToken");

            console.log(API_ENDPOINTS.GET_ID + `/${searchQuery}`)
            const response = await axios.get(API_ENDPOINTS.GET_ID + `/${searchQuery}`, {
                headers: { Authorization: `Bearer ${token}` },
            });

            console.log("fetchIdWithQuery:", response.data);
            setSelectedContact(response.data);

        } catch (error) {
            console.error("Error fetching users", error);
        }
    }

    const fetchContactsFromQuery = async () => {
        if (searchQuery === "") {
            setQueryContactList([])
            return;
        }
        try {
            const token = sessionStorage.getItem("jwtToken");
            console.log(API_ENDPOINTS.SEARCH_CONTACT + `/${searchQuery}`)
            const response = await axios.get(API_ENDPOINTS.SEARCH_CONTACT + `/${searchQuery}`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            console.log("Setting Query Contact List");
            setTestResponse(response);  
            setQueryContactList(response.data)
        } catch (error) {
            console.error(error.message);
        } finally{
            console.log()
        }
    }

    useEffect(() => {
        const token = sessionStorage.getItem("jwtToken");
        const email = jwtDecode(token).sub;
        axios.get(API_ENDPOINTS.GET_ID + `/${email}`, {
            headers: { Authorization: `Bearer ${token}` },
        })
            .then((response) => {
                setLoggedUserId(response.data);
            })
            .catch((error) => {
                console.error("Error fetching users", error);
            });
    }, []);

    useEffect(() => {
        console.log("SELECTED " + selectedContact);
    }, [selectedContact])

    useEffect(() => {
        console.log("response " + testResponse);
        console.log(queryContactList); // TODO: Remove this
    }, [testResponse])


    useEffect(() => {
        fetchContactsFromQuery();
    }, [searchQuery])

    useEffect(() => {
        fetchContactList();
    }, []);

    useEffect(() => {
        let found = false;
        console.log("SELECTED : ", selectedContact)
        console.log(contactList)
        contactList.forEach((contact, i) => {
            console.log(i, "th Contact")
            if (contact.id === selectedContact) {
                console.log("Found", contact)
                found = true;
            }
        })
        if (!found) {
            fetchSelectedContact();
        }
        fetchChatMessages();
    }, [selectedContact]);

    const loggy = () => {
        console.log("LLLLLLL");
    }

    return (

        <div className="container">
            <input type="text dropdown" placeholder="Enter Contact Email" value={searchQuery} onChange={handleQueryChange} onKeyDown={handleQueryEnter} className="form-control m-2" onFocus={() => setIsQueryFocused(true)} onBlur={() => setTimeout(() => setIsQueryFocused(false), 300)}></input>
            <div className={`dropdown-menu p-2 ${isQueryFocused &&   !(queryContactList.length == 0) ? "show" : ""}`}>
                {queryContactList.map((contact) => (
                    <div className="dropdown-item" onClick={() => { setSelectedContact(contact.id) }}>
                        {`${contact.firstName} ${contact.lastName} <${contact.email}>`}
                    </div>
                ))}
            </div>
            <div className="card bg-light">
                <div className="card-header">
                    <h5>Chat</h5>
                </div>
                <div className="d-flex flex-row justify-content-between">
                    <div className="container p-2 w-50">
                        {contactList.map((contact) => (
                            <div className={`card card-sm border m-2 ${contact.id === selectedContact ? "bg-dark text-white" : "bg-light text-black"}`} onClick={() => handleContactClick(contact.id)}>
                                <div className="card-body" style={{ cursor: "pointer" }}>
                                    <div className="card-title d-flex justify-content-between">
                                        <h6> {contact.firstName} {contact.lastName} </h6>
                                        <span style={{ color: "red", fontStyle: "italic" }}>{contact.role.includes("ADMIN") ? "Admin" : ""}</span>
                                    </div>
                                </div>
                            </div>
                        ))}

                    </div>

                    <div className="vr"></div>

                    <div className="container p-0">
                        <div className="card-body overflow-auto " style={{ height: "500px" }}>
                            {isChatMessagesLoading ?
                                <div className="d-flex justify-content-center align-items-center">
                                    <div className="spinner-grow"></div>
                                </div>
                                :
                                chatMessages.map((message) => {
                                    let cleanedTime = message.time.split(".")[0]; // Remove fractional seconds
                                    let messageTime = new Date(cleanedTime);
                                    let formattedTime = `${messageTime.getHours()}:${messageTime.getMinutes()} ${messageTime.getHours() > 12 ? "PM" : "AM"}`;
                                    return (
                                        <div className={`d-flex m-1 justify-content-${message.receiverId === selectedContact ? 'end' : 'start'}`} >
                                            <div className={`column text-${message.receiverId === selectedContact ? 'end' : 'start'}`}>
                                                <div className={`card p-1 m-1 rounded-1 ${message.receiverId === selectedContact ? 'bg-light ps-4' : 'bg-secondary text-white pe-4'}`} style={{ width: "fit-content" }}>
                                                    <span className="card-body p-1">{message.message}</span>
                                                </div>
                                                <span className="text-muted small m-1">{formattedTime}</span>
                                            </div>
                                        </div>
                                    );
                                })
                            }
                        </div>

                        <div className="card-footer">
                            <div className="input-group">
                                <input className="form-control" onChange={handleMessageChange} value={typedMessage} onKeyDown={handleMessageEnter}></input>
                                <button type="button" className="btn btn-primary" onClick={handleMessageSend}>Send</button>
                            </div>
                        </div>

                    </div>
                </div>
            </div>
        </div>

    );
}

export default Chat;
