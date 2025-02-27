package com.ems.util;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class StatusCounts {
    int activeUsers;
    int inactiveUsers;
    int pendingUsers;
}
