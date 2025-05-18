---
title: "GynvaelEN - Mission 14 - Solution"
date: 2017-08-14T06:36:37.000Z
tags:
  - "gynvael"
  - "mission"
feature_image: "content/images/2017/08/mission_14.webp"
---

# GynvaelEN - Mission 14 - Solution

Stream: <https://www.youtube.com/watch?v=rhsH-snYkIc>
Mission link: <https://goo.gl/oUg99i>

> Damn it, how will I ever get out of this labyrinth?
>  ― Simón Bolívar

This mission in comparison to the [previous one](http://ctfs.ghost.io/gynvael-en-mission-13-solution/) was an easy one. This was a PPC category (programming).

In this one we're give a [log file](goo.gl/uQjX3H) and the [application](goo.gl/yz4hJb) that produced it. So our task is to retrieve the initial map.

So we write our script based on what we see in the log and what we know from analyzing the application - the only thing that might be a bit more difficult is that the maze is traversed recursively so we need to have the same approach in our script. I've decided to use a stack to store the visited location and then when we go back pop it up from the stack.

[View Gist](https://gist.github.com/pawlos/5159a4a856ef0b3925c16079074ee0a2)

And basically that's all!

After running the script we retrieve the map (just needed to manually set the map limits):
[code]
    #########################################################
    #.#.#.....##.#..........#.#.#...#..#.......#.......##.#.#
    #.#.#.#.#.##.####.####.##.#.#.#....#######.#.#####..#.#.#
    #...#.#.#..........#....#.#.######.#.#.#...#.#...#.##.#.#
    #.#.#########.####.######.#..........#.#.###.###.####.#.#
    #.#.......#.#.##.#....#...#.########.#.#.#.#..........#.#
    #.###.###.#......#.##....##..#.....#.........###.######.#
    #...#.#.#.#..#.#.#..####....##.##.##.###.###.#.#..#..#..#
    #####.#.#.####.####.#..#.##.#..##......#.#.###.##.##...##
    ........#...........##....#.#.###.##.###........#....####
    ###.#####################################################
    ###.##..................................................#
    #....#..................................................#
    #.##.#....###............####............##......####...#
    #..#.#....##............######...........##.....##..##..#
    #.##.#...##......##.##..######...........##.##..##..##..#
    #.#..#..#####.....###...######..######...##.##......##..#
    #.####..######..#######.######...........##.##.....##...#
    #....#..######....###....#####..######..##..##....##....#
    ####.#..######...##.##.....##...........#######..##.....#
    #....#..######............##................##..##......#
    #.####...####............###................##..######..#
    #.#.##..................................................#
    #.......................................................#
    #########################################################
[/code]
