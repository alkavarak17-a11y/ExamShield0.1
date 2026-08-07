// ==========================================
// EXAMSHIELD - TRANSIT TRACKING SCRIPT
// ==========================================
// Leaflet GPS map + route + checkpoint markers
// + responsive sidebar + timeline animation
// ==========================================

document.addEventListener("DOMContentLoaded", function () {

    // ==========================================
    // 1. MOBILE SIDEBAR TOGGLE
    // ==========================================

    const menuBtn = document.getElementById("mobile-menu-btn");
    const sidebar = document.getElementById("mysidenav");
    const icon = document.getElementById("menu-icon");

    if (menuBtn && sidebar && icon) {

        menuBtn.onclick = function () {

            sidebar.classList.toggle("active");

            if (sidebar.classList.contains("active")) {
                icon.classList.remove("fa-bars");
                icon.classList.add("fa-xmark");
            } else {
                icon.classList.remove("fa-xmark");
                icon.classList.add("fa-bars");
            }

        };
    }


    // ==========================================
    // 2. LEAFLET MAP
    // ==========================================

    const mapContainer = document.getElementById("tracking-map");

    if (!mapContainer) {
        console.error("ERROR: #tracking-map was not found.");
        return;
    }


    // ==========================================
    // 3. GET ROUTE DATA FROM FLASK
    // ==========================================

    let routeData = [];

    if (
        typeof TRACKING_ROUTE_DATA !== "undefined" &&
        Array.isArray(TRACKING_ROUTE_DATA)
    ) {
        routeData = TRACKING_ROUTE_DATA;
    }

    console.log("EXAMSHIELD Tracking Route Data:", routeData);


    // ==========================================
    // 4. CREATE MAP
    // ==========================================

    const map = L.map("tracking-map", {
        zoomControl: true
    }).setView([19.0760, 72.8777], 6);


    // ==========================================
    // 5. ADD OPENSTREETMAP TILES
    // ==========================================
    // IMPORTANT:
    // This must be added even when routeData is empty.
    // Otherwise Leaflet shows only the + / - buttons
    // and the map remains blank.
    // ==========================================

    L.tileLayer(
        "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",
        {
            maxZoom: 19,
            attribution: "&copy; OpenStreetMap contributors"
        }
    ).addTo(map);


    // ==========================================
    // 6. CHECK WHETHER ROUTE DATA EXISTS
    // ==========================================

    if (routeData.length === 0) {

        console.warn(
            "EXAMSHIELD: route_data is empty. Showing default map."
        );

        // Force Leaflet to calculate the container size
        setTimeout(function () {
            map.invalidateSize();
        }, 300);

    } else {

        // ==========================================
        // 7. VALIDATE GPS DATA
        // ==========================================

        const validPoints = routeData.filter(function (point) {

            const lat = Number(point.lat);
            const lng = Number(point.lng);

            return (
                Number.isFinite(lat) &&
                Number.isFinite(lng) &&
                lat >= -90 &&
                lat <= 90 &&
                lng >= -180 &&
                lng <= 180
            );

        });


        console.log(
            "EXAMSHIELD Valid GPS Points:",
            validPoints
        );


        if (validPoints.length === 0) {

            console.error(
                "ERROR: route_data exists but contains no valid latitude/longitude values."
            );

        } else {

            // ==========================================
            // 8. CREATE LAT/LNG ARRAY
            // ==========================================

            const latlngs = validPoints.map(function (point) {

                return [
                    Number(point.lat),
                    Number(point.lng)
                ];

            });


            // ==========================================
            // 9. DRAW GPS POLYLINE
            // ==========================================

            const polyline = L.polyline(
                latlngs,
                {
                    color: "#3b82f6",
                    weight: 4,
                    dashArray: "8, 10",
                    opacity: 0.85
                }
            ).addTo(map);


            // ==========================================
            // 10. FIT MAP TO ROUTE
            // ==========================================

            map.fitBounds(
                polyline.getBounds(),
                {
                    padding: [50, 50]
                }
            );


            // ==========================================
            // 11. CREATE CHECKPOINT MARKERS
            // ==========================================

            validPoints.forEach(function (point, idx) {

                const lat = Number(point.lat);
                const lng = Number(point.lng);

                const isOrigin = idx === 0;

                const isDestination =
                    idx === validPoints.length - 1;

                const pointStatus =
                    String(point.status || "").toLowerCase();

                const isCurrent =
                    pointStatus.includes("current") ||
                    pointStatus.includes("transit") ||
                    pointStatus.includes("in transit");


                let marker;


                // ======================================
                // CURRENT VEHICLE
                // ======================================

                if (isCurrent) {

                    marker = L.circleMarker(
                        [lat, lng],
                        {
                            radius: 10,
                            color: "#2563eb",
                            fillColor: "#3b82f6",
                            fillOpacity: 0.9,
                            weight: 3
                        }
                    ).addTo(map);


                    marker.bindPopup(`
                        <div style="
                            font-family:'Poppins',sans-serif;
                            min-width:180px;
                        ">

                            <span style="
                                display:inline-block;
                                padding:3px 8px;
                                background:#1e3a8a;
                                color:#93c5fd;
                                border-radius:4px;
                                font-size:10px;
                                font-weight:600;
                                margin-bottom:5px;
                            ">
                                SHIELD CARRIER
                            </span>

                            <h4 style="
                                margin:0 0 5px;
                                color:#2563eb;
                            ">
                                Current GPS Signal
                            </h4>

                            <p style="
                                margin:2px 0;
                                font-size:12px;
                            ">
                                Sector:
                                <b>
                                    ${point.location_name || "Unknown"}
                                </b>
                            </p>

                            <p style="
                                margin:2px 0;
                                font-size:12px;
                            ">
                                Status:
                                <b style="color:#f59e0b;">
                                    In Transit
                                </b>
                            </p>

                            <p style="
                                margin:2px 0;
                                font-size:11px;
                                color:#64748b;
                            ">
                                GPS:
                                ${lat.toFixed(5)},
                                ${lng.toFixed(5)}
                            </p>

                        </div>
                    `);

                }


                // ======================================
                // NORMAL CHECKPOINT
                // ======================================

                else {

                    let nodeColor = "#64748b";
                    let nodeTitle = "Transit Stopover";


                    if (isOrigin) {

                        nodeColor = "#10b981";
                        nodeTitle = "Origin Vault";

                    } else if (isDestination) {

                        nodeColor = "#a78bfa";
                        nodeTitle = "Target Destination";

                    }


                    marker = L.circleMarker(
                        [lat, lng],
                        {
                            radius: 7,
                            color: nodeColor,
                            fillColor: nodeColor,
                            fillOpacity: 0.8,
                            weight: 2
                        }
                    ).addTo(map);


                    marker.bindPopup(`
                        <div style="
                            font-family:'Poppins',sans-serif;
                            min-width:170px;
                        ">

                            <h5 style="
                                margin:0 0 5px;
                                color:${nodeColor};
                            ">
                                ${nodeTitle}
                            </h5>

                            <p style="
                                margin:2px 0;
                                font-size:12px;
                                color:#1e293b;
                            ">
                                <b>
                                    ${point.location_name || "Unknown"}
                                </b>
                            </p>

                            <p style="
                                margin:2px 0;
                                font-size:11px;
                                color:#64748b;
                            ">
                                Sequence:
                                Step ${idx + 1}
                            </p>

                            <p style="
                                margin:2px 0;
                                font-size:11px;
                                color:#64748b;
                            ">
                                GPS:
                                ${lat.toFixed(5)},
                                ${lng.toFixed(5)}
                            </p>

                        </div>
                    `);
                }

            });


            // ==========================================
            // 12. FORCE MAP RESIZE
            // ==========================================

            setTimeout(function () {
                map.invalidateSize();
            }, 300);

        }

    }


    // ==========================================
    // 13. TIMELINE PROGRESS
    // ==========================================

    adjustTimelineProgress();


    // ==========================================
    // 14. TIMELINE ANIMATION
    // ==========================================

    const items =
        document.querySelectorAll(".timeline-item");


    items.forEach(function (item) {

        item.style.opacity = "0";
        item.style.transform = "translateY(20px)";

    });


    items.forEach(function (item, index) {

        setTimeout(function () {

            item.style.opacity = "1";
            item.style.transform = "translateY(0)";

        }, index * 350);

    });

});


// ==========================================
// TIMELINE PROGRESS FUNCTION
// ==========================================

function adjustTimelineProgress() {

    const timeline =
        document.querySelector(".transit-timeline");

    const completedItems =
        document.querySelectorAll(
            ".timeline-item.completed"
        );

    const currentItem =
        document.querySelector(
            ".timeline-item.current"
        );


    if (!timeline) {
        return;
    }


    // Create progress line if it doesn't exist

    let progress =
        document.querySelector(
            ".timeline-progress-bar"
        );


    if (!progress) {

        progress =
            document.createElement("div");

        progress.className =
            "timeline-progress-bar";

        timeline.appendChild(progress);

    }


    const totalItems =
        document.querySelectorAll(
            ".timeline-item"
        );


    if (totalItems.length === 0) {

        progress.style.height = "0px";

        return;
    }


    // ==========================================
    // CURRENT CHECKPOINT
    // ==========================================

    if (currentItem) {

        let currentIndex = 0;


        totalItems.forEach(
            function (item, index) {

                if (item === currentItem) {
                    currentIndex = index;
                }

            }
        );


        const denominator =
            totalItems.length - 1 || 1;


        const timelineHeight =
            timeline.offsetHeight;


        progress.style.height =
            `${(
                currentIndex /
                denominator
            ) * (timelineHeight - 20)}px`;

    }


    // ==========================================
    // ALL COMPLETED
    // ==========================================

    else if (
        completedItems.length ===
        totalItems.length
    ) {

        progress.style.height = "100%";

    }


    // ==========================================
    // NOTHING COMPLETED
    // ==========================================

    else {

        progress.style.height = "0px";

    }

}